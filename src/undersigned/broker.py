"""The broker side: record what the human granted, then sign requests inside it."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Mapping

from undersigned import httpsig, tokens
from undersigned.errors import Denied, UndersignedError, StepUpRequired
from undersigned.evidence import HumanEvidence, verify_evidence
from undersigned.grant import Budget, Grant, PinnedRequest
from undersigned.keys import SigningKey, jwks
from undersigned.outbox import Outbox
from undersigned.policy import ALLOW, STEP_UP, GrantState, evaluate, record_use

SIGNATURE_TAG = "grant-proof"
SIGNED_COMPONENTS = ("@method", "@target-uri", "content-digest", "grant-proof")


@dataclass(frozen=True)
class ServiceEndpoints:
    """Where a service receives grant receipts and revocation events."""

    grants_url: str
    events_url: str


@dataclass
class _Record:
    grant: Grant
    state: GrantState
    evidence: HumanEvidence | None = None
    active: bool = False
    revoked_at: int | None = None


class Broker:
    """Holds grants and signs the requests an agent makes under them.

    ``risk_of(action)`` and ``cost_of(action, body)`` are the broker's own
    catalog of what each action is and what it draws from a budget. The agent
    asking for a signature never supplies either.

    State is kept in memory. A real deployment would persist ``_records`` and
    the outbox; nothing else here is stateful.
    """

    def __init__(
        self,
        *,
        issuer: str,
        key: SigningKey,
        rp_id: str,
        origin: str,
        risk_of: Callable[[str], str | None],
        cost_of: Callable[[str, bytes], int] = lambda action, body: 0,
        services: Mapping[str, ServiceEndpoints] | None = None,
        outbox: Outbox | None = None,
        clock: Callable[[], float] = time.time,
        proof_ttl: int = 30,
    ):
        self.issuer = issuer
        self.key = key
        self.rp_id = rp_id
        self.origin = origin
        self._risk_of = risk_of
        self._cost_of = cost_of
        self.services = dict(services or {})
        self.outbox = outbox
        self._clock = clock
        self._proof_ttl = proof_ttl
        self._records: dict[str, _Record] = {}

    def _now(self) -> int:
        return int(self._clock())

    def jwks(self) -> dict:
        return jwks(self.key)

    def _record(self, grant_id: str) -> _Record:
        try:
            return self._records[grant_id]
        except KeyError:
            raise Denied("no such grant", code="grant_not_found") from None

    # -- granting ------------------------------------------------------------

    def propose(
        self,
        *,
        audience: str,
        subject: str,
        actions: tuple[str, ...] | list[str],
        duration: int,
        max_risk: str = "low",
        budget: Budget | None = None,
        first_use_confirmation: bool = False,
        single_use: bool = False,
        request: PinnedRequest | None = None,
    ) -> Grant:
        """Draft a grant for the human to review. Nothing is authorized yet.

        Show the human the grant, then run a passkey ceremony with
        ``grant.digest()`` as the challenge and pass the result to
        :meth:`activate`.
        """
        now = self._now()
        grant = Grant(
            issuer=self.issuer,
            audience=audience,
            subject=subject,
            actions=tuple(actions),
            issued_at=now,
            expires_at=now + duration,
            max_risk=max_risk,
            budget=budget,
            first_use_confirmation=first_use_confirmation,
            single_use=single_use,
            request=request,
        )
        self._records[grant.grant_id] = _Record(grant=grant, state=GrantState())
        return grant

    def activate(
        self,
        grant_id: str,
        evidence: HumanEvidence | None = None,
        *,
        credential_public_key: bytes | None = None,
    ) -> str:
        """Activate a proposed grant and return its signed receipt.

        With ``evidence`` the receipt carries the human's own signature over the
        grant, checked here first. Without it the grant is broker-attested only,
        and a service may refuse it.
        """
        record = self._record(grant_id)
        if record.state.revoked:
            raise Denied("grant was revoked", code="grant_revoked")
        if record.active:
            raise Denied("grant is already active", code="grant_already_active")
        if evidence is not None:
            if credential_public_key is None:
                raise UndersignedError("credential_public_key is required to check evidence")
            verify_evidence(
                evidence,
                challenge=record.grant.digest(),
                rp_id=self.rp_id,
                origin=self.origin,
                credential_public_key=credential_public_key,
            )
        record.evidence = evidence
        record.active = True
        receipt = self.receipt(grant_id)
        endpoints = self.services.get(record.grant.audience)
        if self.outbox is not None and endpoints is not None:
            self.outbox.enqueue(endpoints.grants_url, tokens.RECEIPT_MEDIA_TYPE, receipt)
        return receipt

    def receipt(self, grant_id: str) -> str:
        """Re-issue the receipt for an active grant, e.g. after ``unknown_grant``."""
        record = self._record(grant_id)
        if not record.active:
            raise Denied("grant is not active", code="grant_not_active")
        if record.state.revoked:
            raise Denied("grant was revoked", code="grant_revoked")
        return tokens.encode_receipt(
            self.key,
            document=record.grant.to_document(),
            evidence=record.evidence.to_dict() if record.evidence else None,
            now=self._now(),
        )

    def confirm_first_use(self, grant_id: str) -> None:
        """Record that the human confirmed the first action under this grant."""
        self._record(grant_id).state.first_use_confirmed = True

    def revoke_account(
        self, audience: str, subject: str, *, initiating_entity: str = "user"
    ) -> list[str]:
        """Revoke every grant an account still holds at one service.

        Grants are independent: revoking a standing grant leaves an unused
        single-use approval valid. This is what "stop everything" should call.
        Returns the revocation events, one per grant.
        """
        now = self._now()
        events = []
        for record in list(self._records.values()):
            grant = record.grant
            if grant.audience != audience or grant.subject != subject:
                continue
            # A single-use grant the broker has already signed for is included:
            # that request may still be on its way to the service.
            if record.state.revoked or now >= grant.expires_at:
                continue
            events.append(self.revoke(grant.grant_id, initiating_entity=initiating_entity))
        return events

    def forget(self, grant_id: str) -> None:
        """Drop a grant's record, e.g. after it expires or its account is closed."""
        self._records.pop(grant_id, None)

    # -- acting --------------------------------------------------------------

    def authorize(
        self,
        grant_id: str,
        *,
        action: str,
        method: str,
        url: str,
        body: bytes,
    ) -> dict[str, str]:
        """Check the action against the grant and return headers that prove it.

        Send the returned headers with exactly this method, URL and body.
        Raises :class:`StepUpRequired` when the human must approve this action
        individually, and :class:`Denied` when the grant cannot be used at all.
        The action is counted against the grant as soon as this returns.
        """
        record = self._record(grant_id)
        grant = record.grant
        if not record.active:
            raise Denied("grant is not active", code="grant_not_active")
        risk = self._risk_of(action)
        if risk is None:
            raise Denied(f"unknown action {action!r}", code="unknown_action")
        amount = self._cost_of(action, body)
        now = self._now()
        digest_header = httpsig.content_digest(body)
        decision = evaluate(
            grant, record.state, action=action, risk=risk, amount=amount, now=now,
            method=method, url=url, content_digest=digest_header,
        )
        if decision.outcome == STEP_UP:
            raise StepUpRequired(f"{action}: {decision.reason}", code=decision.reason)
        if decision.outcome != ALLOW:
            raise Denied(f"{action}: {decision.reason}", code=decision.reason)
        record_use(grant, record.state, amount=amount, now=now)

        proof = tokens.encode_proof(
            self.key,
            issuer=self.issuer,
            audience=grant.audience,
            subject=grant.subject,
            grant_id=grant.grant_id,
            grant_digest=grant.digest_hex(),
            action=action,
            amount=amount,
            now=now,
            ttl=self._proof_ttl,
        )
        headers = {"Content-Digest": digest_header, tokens.PROOF_HEADER: proof}
        headers.update(httpsig.sign_request(
            self.key,
            method=method,
            url=url,
            headers=headers,
            components=SIGNED_COMPONENTS,
            created=now,
            expires=now + self._proof_ttl,
            tag=SIGNATURE_TAG,
        ))
        return headers

    # -- revoking ------------------------------------------------------------

    def revoke(self, grant_id: str, *, initiating_entity: str = "user") -> str:
        """Revoke a grant now and return the signed revocation event.

        ``initiating_entity`` is one of ``user``, ``admin``, ``policy`` or
        ``system`` (the values Shared Signals events use).

        Revocation takes effect at the broker immediately. The event is queued
        for the service so it can stop honoring the grant on its side too.
        """
        if initiating_entity not in ("user", "admin", "policy", "system"):
            raise ValueError("initiating_entity must be user, admin, policy or system")
        record = self._record(grant_id)
        now = self._now()
        if not record.state.revoked:
            record.state.revoked = True
            record.revoked_at = now
        grant = record.grant
        event = tokens.encode_revocation(
            self.key,
            issuer=self.issuer,
            audience=grant.audience,
            subject=grant.subject,
            grant_id=grant.grant_id,
            grant_digest=grant.digest_hex(),
            initiating_entity=initiating_entity,
            revoked_at=record.revoked_at or now,
            now=now,
        )
        endpoints = self.services.get(grant.audience)
        if self.outbox is not None and endpoints is not None:
            self.outbox.enqueue(endpoints.events_url, tokens.SET_MEDIA_TYPE, event)
        return event
