"""The service side: verify, independently, that a human authorized this request."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

from undersigned import httpsig, tokens
from undersigned.broker import SIGNATURE_TAG, SIGNED_COMPONENTS
from undersigned.errors import Denied, EvidenceError, InvalidGrant, SignatureError, UnknownGrant
from undersigned.evidence import HumanEvidence, verify_evidence
from undersigned.grant import Grant
from undersigned.keys import KeySet
from undersigned.policy import GrantState, evaluate, record_use


@dataclass(frozen=True)
class BrokerTrust:
    """What a service knows about a broker it accepts grants from."""

    keys: KeySet
    rp_id: str  #: the WebAuthn relying-party id the broker's passkeys are bound to
    origin: str  #: the origin of the broker's approval page


@dataclass(frozen=True)
class VerifiedAction:
    """The outcome of a successful check, plus what to keep as evidence."""

    grant: Grant
    subject: str
    action: str
    amount: int
    human_verified: bool
    proof_id: str
    #: Everything needed to re-verify this request later: store it with the
    #: request body (and the grant receipt) as the audit record.
    record: dict = field(compare=False)


@dataclass
class _Held:
    grant: Grant
    state: GrantState
    human_verified: bool
    receipt: str


class Verifier:
    """Checks grant receipts, per-request proofs and revocation events.

    State is kept in memory. A real deployment would persist the pinned
    passkeys, the grants with their counters, and revocations.
    """

    def __init__(
        self,
        *,
        audience: str,
        brokers: Mapping[str, BrokerTrust],
        risk_of: Callable[[str], str | None],
        require_human_evidence: bool = True,
        clock: Callable[[], float] = time.time,
        leeway: int = 5,
    ):
        self.audience = audience
        self.brokers = dict(brokers)
        self._risk_of = risk_of
        self.require_human_evidence = require_human_evidence
        self._clock = clock
        self._leeway = leeway
        self._passkeys: dict[tuple[str, str], bytes] = {}
        # Grants and revocations are keyed by (issuer, grant_id), so one broker
        # cannot touch another broker's grants by reusing an id.
        self._grants: dict[tuple[str, str], _Held] = {}
        self._revoked: set[tuple[str, str]] = set()
        self._seen_proofs: dict[str, int] = {}  # jti -> expiry

    def _now(self) -> int:
        return int(self._clock())

    def _trust(self, token: str) -> tuple[str, BrokerTrust]:
        issuer = tokens.peek_issuer(token)
        trust = self.brokers.get(issuer)
        if trust is None:
            raise SignatureError("issuer is not a trusted broker", code="untrusted_issuer")
        return issuer, trust

    # -- account linking -----------------------------------------------------

    def pin_passkey(self, subject: str, credential_id: str, cose_public_key: bytes) -> None:
        """Record a passkey as belonging to one of this service's accounts.

        Do this when the account is linked to the broker, over a channel the
        service trusts. From then on only that authenticator can sign grants
        for the account; a broker signing key alone is not enough.
        """
        self._passkeys[(subject, credential_id)] = cose_public_key

    # -- grant receipts ------------------------------------------------------

    def accept_grant(self, receipt: str) -> Grant:
        """Verify and store a grant receipt. Safe to call again with the same grant."""
        issuer, trust = self._trust(receipt)
        claims = tokens.decode(
            receipt, trust.keys, typ=tokens.RECEIPT_TYP, issuer=issuer, audience=self.audience,
            now=self._now(), leeway=self._leeway, expires=False,
        )
        grant = Grant.from_document(claims.get("grant"))
        if grant.issuer != issuer or grant.audience != self.audience:
            raise InvalidGrant("grant issuer or audience does not match the receipt")
        digest = grant.digest_hex()

        key = (issuer, grant.grant_id)
        if key in self._revoked:
            raise Denied("grant was revoked", code="grant_revoked")
        held = self._grants.get(key)
        if held is not None:
            if held.grant.digest_hex() != digest:
                raise InvalidGrant("a different grant with this id already exists")
            return held.grant

        human_verified = False
        raw_evidence = claims.get("evidence")
        if raw_evidence is not None:
            evidence = HumanEvidence.from_dict(raw_evidence)
            public_key = self._passkeys.get((grant.subject, evidence.credential_id))
            if public_key is None:
                raise EvidenceError("passkey is not pinned to this account", code="unknown_passkey")
            verify_evidence(
                evidence, challenge=grant.digest(), rp_id=trust.rp_id, origin=trust.origin,
                credential_public_key=public_key,
            )
            human_verified = True
        elif self.require_human_evidence:
            raise EvidenceError("grant has no human evidence", code="human_evidence_required")

        self._grants[key] = _Held(grant, GrantState(), human_verified, receipt)
        return grant

    # -- requests ------------------------------------------------------------

    def verify_request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> VerifiedAction:
        """Verify one incoming request. Raises unless every check passes.

        ``url`` is the absolute URL the service is addressed by, as the broker
        sent it. On success the action is counted against the grant.
        """
        now = self._now()
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
        proof = lowered.get(tokens.PROOF_HEADER.lower())
        if not proof:
            raise SignatureError("request carries no proof", code="proof_missing")
        proof = proof.strip()
        issuer, trust = self._trust(proof)

        # 1. The broker signed this method, URL, body and proof together.
        signature = httpsig.verify_request(
            trust.keys, method=method, url=url, headers=lowered, body=body,
            required_components=SIGNED_COMPONENTS, tag=SIGNATURE_TAG, now=now,
            leeway=self._leeway,
        )
        # 2. The proof itself is a current token for this service.
        claims = tokens.decode(
            proof, trust.keys, typ=tokens.PROOF_TYP, issuer=issuer, audience=self.audience,
            now=now, leeway=self._leeway,
        )
        self._forget_expired_proofs(now)
        proof_id = claims["jti"]
        if proof_id in self._seen_proofs:
            raise Denied("proof was already used", code="proof_replayed")

        # 3. It refers to a grant this service holds, unchanged.
        action, amount = _action_of(claims, self.audience)
        reference = claims.get("grant")
        if not isinstance(reference, dict):
            raise SignatureError("proof names no grant", code="token_malformed")
        key = (issuer, reference.get("id"))
        if key in self._revoked:
            raise Denied("grant was revoked", code="grant_revoked")
        held = self._grants.get(key)
        if held is None:
            raise UnknownGrant("send the grant receipt first")
        grant = held.grant
        if reference.get("digest") != grant.digest_hex():
            raise Denied("proof does not match the stored grant", code="grant_mismatch")
        if claims.get("sub") != grant.subject:
            raise Denied("proof subject does not match the grant", code="subject_mismatch")

        # 4. The action fits the envelope the human signed, by this service's
        #    own reckoning of risk and spend.
        risk = self._risk_of(action)
        if risk is None:
            raise Denied(f"unknown action {action!r}", code="unknown_action")
        decision = evaluate(
            grant, held.state, action=action, risk=risk, amount=amount, now=now,
            content_digest=httpsig.content_digest(body), enforce_first_use=False,
            leeway=self._leeway,
        )
        if not decision.allowed:
            raise Denied(f"{action}: {decision.reason}", code=decision.reason)

        record_use(grant, held.state, amount=amount, now=now)
        self._seen_proofs[proof_id] = claims["exp"] + self._leeway
        return VerifiedAction(
            grant=grant,
            subject=grant.subject,
            action=action,
            amount=amount,
            human_verified=held.human_verified,
            proof_id=proof_id,
            record={
                "method": method,
                "url": url,
                "content_digest": lowered["content-digest"],
                "grant_proof": proof,
                "signature_input": lowered["signature-input"],
                "signature": lowered["signature"],
                "signature_keyid": signature.keyid,
                "issuer": issuer,
                "grant_id": grant.grant_id,
                "grant_digest": grant.digest_hex(),
                "verified_at": now,
            },
        )

    def _forget_expired_proofs(self, now: int) -> None:
        for proof_id in [p for p, expiry in self._seen_proofs.items() if expiry < now]:
            del self._seen_proofs[proof_id]

    # -- revocation ----------------------------------------------------------

    def accept_event(self, event: str) -> str:
        """Apply a revocation event and return the revoked grant id.

        Idempotent. A revocation that arrives before its grant is remembered,
        so the grant is refused if its receipt turns up later.
        """
        issuer, trust = self._trust(event)
        claims = tokens.decode(
            event, trust.keys, typ=tokens.SET_TYP, issuer=issuer, audience=self.audience,
            now=self._now(), leeway=self._leeway, expires=False,
        )
        events = claims.get("events")
        payload = events.get(tokens.EVENT_GRANT_REVOKED) if isinstance(events, dict) else None
        if not isinstance(payload, dict) or not isinstance(payload.get("grant_id"), str):
            raise SignatureError("not a grant-revoked event", code="unsupported_event")
        grant_id = payload["grant_id"]
        self._revoked.add((issuer, grant_id))
        held = self._grants.get((issuer, grant_id))
        if held is not None:
            held.state.revoked = True
        return grant_id

    def receipt_for(self, issuer: str, grant_id: str) -> str | None:
        """The stored receipt for a grant, for the audit record."""
        held = self._grants.get((issuer, grant_id))
        return held.receipt if held else None

    def is_revoked(self, issuer: str, grant_id: str) -> bool:
        return (issuer, grant_id) in self._revoked


def push_error(exc: Exception) -> dict[str, str]:
    """The RFC 8935 error body (sent with HTTP 400) for a rejected event."""
    code = getattr(exc, "code", "")
    err = {
        "untrusted_issuer": "invalid_issuer",
        "unknown_key": "invalid_key",
    }.get(code, "invalid_request")
    if code == "token_invalid" and "audience" in str(exc).lower():
        err = "invalid_audience"
    return {"err": err, "description": str(exc)}


def _action_of(claims: dict, audience: str) -> tuple[str, int]:
    details = claims.get("authorization_details")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        raise SignatureError("proof must describe exactly one action", code="token_malformed")
    detail = details[0]
    actions = detail.get("actions")
    amount = detail.get("amount", 0)
    if (
        detail.get("type") != tokens.ACTION_DETAIL_TYPE
        or detail.get("locations") != [audience]
        or not isinstance(actions, list)
        or len(actions) != 1
        or not isinstance(actions[0], str)
        or isinstance(amount, bool)
        or not isinstance(amount, int)
    ):
        raise SignatureError("proof must describe exactly one action", code="token_malformed")
    return actions[0], amount
