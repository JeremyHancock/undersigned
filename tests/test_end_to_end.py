"""Broker and service wired together the way an integration would be."""

import jwt
import pytest

from undersigned import tokens
from undersigned.broker import Broker, ServiceEndpoints
from undersigned.errors import (
    Denied, EvidenceError, UndersignedError, InvalidGrant, SignatureError, StepUpRequired,
    UnknownGrant,
)
from undersigned.grant import Budget
from undersigned.httpsig import content_digest
from undersigned.keys import KeySet, SigningKey
from undersigned.outbox import Outbox
from undersigned.service import BrokerTrust, Verifier, push_error
from undersigned.testing import SoftAuthenticator

ISSUER = "https://broker.example"
SERVICE = "https://notes.example"
RP_ID = "broker.example"
URL = "https://notes.example/v1/notes"
BODY = b'{"title":"hello"}'
ACCOUNT = "acct_42"
RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class World:
    """One broker, one service, one human with a passkey."""

    def __init__(self, **verifier_options):
        self.clock = Clock()
        self.key = SigningKey.generate()
        self.sent = []
        self.service_up = True
        self.outbox = Outbox(self._send, clock=self.clock)
        self.broker = Broker(
            issuer=ISSUER, key=self.key, rp_id=RP_ID, origin=ISSUER, clock=self.clock,
            outbox=self.outbox,
            services={SERVICE: ServiceEndpoints(f"{SERVICE}/grants", f"{SERVICE}/events")},
        )
        self.verifier = Verifier(
            audience=SERVICE,
            brokers={ISSUER: BrokerTrust(KeySet.from_jwks(self.broker.jwks()), RP_ID, ISSUER)},
            risk_of=RISKS.get, clock=self.clock, **verifier_options,
        )
        self.passkey = SoftAuthenticator()
        self.verifier.pin_passkey(ACCOUNT, self.passkey.credential_id, self.passkey.cose_public_key)

    def _send(self, url, body, headers):
        """Stand in for HTTP: hand deliveries straight to the service."""
        if not self.service_up:
            raise OSError("connection refused")
        self.sent.append((url, headers["Content-Type"]))
        token = body.decode()
        try:
            if url.endswith("/grants"):
                self.verifier.accept_grant(token)
                return 201
            self.verifier.accept_event(token)
            return 202
        except UndersignedError:
            return 400

    def grant(self, *, sign=True, **overrides):
        fields = dict(audience=SERVICE, subject=ACCOUNT, actions=["notes.read", "notes.write"],
                      duration=30 * 86_400, max_risk="medium")
        fields.update(overrides)
        grant = self.broker.propose(**fields)
        evidence = None
        if sign:
            evidence = self.passkey.sign(grant.digest(), rp_id=RP_ID, origin=ISSUER)
        self.broker.activate(grant.grant_id, evidence,
                             credential_public_key=self.passkey.cose_public_key)
        return grant

    def call(self, grant, action="notes.write", body=BODY, amount=0, **send_overrides):
        headers = self.broker.authorize(
            grant.grant_id, action=action, risk=RISKS[action], method="POST", url=URL,
            body=body, amount=amount,
        )
        args = dict(method="POST", url=URL, headers=headers, body=body)
        args.update(send_overrides)
        return self.verifier.verify_request(**args)


def code_of(callable_, *args, **kwargs):
    with pytest.raises(UndersignedError) as caught:
        callable_(*args, **kwargs)
    return caught.value.code


# -- the happy path ---------------------------------------------------------


def test_request_inside_a_human_signed_grant_is_verified():
    world = World()
    grant = world.grant()
    verified = world.call(grant)
    assert verified.action == "notes.write" and verified.subject == ACCOUNT
    assert verified.human_verified is True
    assert verified.record["grant_digest"] == grant.digest_hex()
    assert world.verifier.receipt_for(ISSUER, grant.grant_id)
    assert world.sent == [(f"{SERVICE}/grants", "application/jwt")]


def test_proof_token_has_the_documented_shape():
    world = World()
    grant = world.grant()
    headers = world.broker.authorize(grant.grant_id, action="notes.read", risk="low",
                                     method="POST", url=URL, body=BODY)
    proof = headers["Grant-Proof"]
    assert jwt.get_unverified_header(proof)["typ"] == "grant-proof+jwt"
    claims = jwt.decode(proof, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 30
    assert claims["grant"] == {"id": grant.grant_id, "digest": grant.digest_hex()}
    assert claims["authorization_details"][0]["actions"] == ["notes.read"]
    assert headers["Content-Digest"] == content_digest(BODY)


# -- what the service refuses -----------------------------------------------


def test_altered_body_method_or_url_is_refused():
    world = World()
    grant = world.grant()
    assert code_of(world.call, grant, **{"body": BODY, "url": URL + "/other"}) == "invalid_signature"
    headers = world.broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                                     method="POST", url=URL, body=BODY)
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=b'{"title":"evil"}') == "digest_mismatch"
    assert code_of(world.verifier.verify_request, method="DELETE", url=URL, headers=headers,
                   body=BODY) == "invalid_signature"


def test_replayed_request_is_refused():
    world = World()
    grant = world.grant()
    headers = world.broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                                     method="POST", url=URL, body=BODY)
    world.verifier.verify_request(method="POST", url=URL, headers=headers, body=BODY)
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=BODY) == "proof_replayed"


def test_stale_request_is_refused():
    world = World()
    grant = world.grant()
    headers = world.broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                                     method="POST", url=URL, body=BODY)
    world.clock.now += 120
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=BODY) == "signature_expired"


def test_request_without_proof_or_from_unknown_broker_is_refused():
    world, stranger = World(), World()
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers={},
                   body=BODY) == "proof_missing"
    grant = stranger.grant()
    headers = stranger.broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                                        method="POST", url=URL, body=BODY)
    # Same issuer name, different key: the service does not hold it.
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=BODY) == "unknown_key"


def test_unknown_grant_can_be_recovered_by_resending_the_receipt():
    world = World()
    world.service_up = False
    grant = world.grant()
    assert code_of(world.call, grant) == UnknownGrant.code
    world.verifier.accept_grant(world.broker.receipt(grant.grant_id))
    assert world.call(grant).action == "notes.write"


# -- the service checks the envelope itself ----------------------------------


def test_service_rejects_a_proof_the_grant_does_not_cover():
    """A broker (or a stolen broker key) claiming more than the human signed."""
    world = World()
    grant = world.grant(actions=["notes.read"], max_risk="low")
    forged = tokens.encode_proof(
        world.key, issuer=ISSUER, audience=SERVICE, subject=ACCOUNT, grant_id=grant.grant_id,
        grant_digest=grant.digest_hex(), action="notes.purge", amount=0,
        now=int(world.clock()), ttl=30,
    )
    from undersigned import httpsig
    from undersigned.broker import SIGNATURE_TAG, SIGNED_COMPONENTS
    headers = {"Content-Digest": content_digest(BODY), "Grant-Proof": forged}
    headers.update(httpsig.sign_request(
        world.key, method="POST", url=URL, headers=headers, components=SIGNED_COMPONENTS,
        created=int(world.clock()), expires=int(world.clock()) + 30, tag=SIGNATURE_TAG))
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=BODY) == "action_not_covered"


def test_service_uses_its_own_risk_rating():
    world = World()
    grant = world.grant(actions=["notes.read", "notes.write"], max_risk="medium")
    RISKS_AT_BROKER = "low"  # the broker under-rates the action
    headers = world.broker.authorize(grant.grant_id, action="notes.write", risk=RISKS_AT_BROKER,
                                     method="POST", url=URL, body=BODY)
    world.verifier._risk_of = {"notes.write": "high"}.get
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=headers,
                   body=BODY) == "risk_exceeds_grant"


def test_service_refuses_a_receipt_whose_grant_was_widened_after_signing():
    world = World()
    grant = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.read"],
                                 duration=3600)
    evidence = world.passkey.sign(grant.digest(), rp_id=RP_ID, origin=ISSUER)
    document = grant.to_document()
    document["authorization_details"][0]["actions"].append("notes.write")
    widened = tokens.encode_receipt(world.key, document=document, evidence=evidence.to_dict(),
                                    now=int(world.clock()))
    assert code_of(world.verifier.accept_grant, widened) == EvidenceError.code


def test_service_refuses_evidence_from_a_passkey_it_never_pinned():
    world = World()
    rogue = SoftAuthenticator()
    grant = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.read"],
                                 duration=3600)
    evidence = rogue.sign(grant.digest(), rp_id=RP_ID, origin=ISSUER)
    receipt = tokens.encode_receipt(world.key, document=grant.to_document(),
                                    evidence=evidence.to_dict(), now=int(world.clock()))
    assert code_of(world.verifier.accept_grant, receipt) == "unknown_passkey"


def test_broker_attested_grants_are_refused_unless_the_service_opts_in():
    strict = World()
    world = World(require_human_evidence=False)
    assert code_of(strict.verifier.accept_grant,
                   _unsigned_receipt(strict)) == "human_evidence_required"
    grant = world.grant(sign=False)
    assert world.call(grant).human_verified is False


def _unsigned_receipt(world):
    grant = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.read"],
                                 duration=3600)
    world.service_up = False
    return world.broker.activate(grant.grant_id)


def test_broker_will_not_activate_a_grant_with_bad_evidence():
    world = World()
    grant = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.read"],
                                 duration=3600)
    other = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.write"],
                                 duration=3600, max_risk="medium")
    evidence = world.passkey.sign(other.digest(), rp_id=RP_ID, origin=ISSUER)
    assert code_of(world.broker.activate, grant.grant_id, evidence,
                   credential_public_key=world.passkey.cose_public_key) == EvidenceError.code
    assert code_of(world.call, grant, action="notes.read") == "grant_not_active"


def test_receipt_for_another_service_is_refused():
    world = World()
    grant = world.broker.propose(audience="https://other.example", subject=ACCOUNT,
                                 actions=["notes.read"], duration=3600)
    receipt = world.broker.activate(grant.grant_id)
    assert code_of(world.verifier.accept_grant, receipt) == "token_invalid"


# -- envelope: budget, first use, punch-through ------------------------------


def test_budget_is_enforced_at_the_broker_and_independently_at_the_service():
    world = World()
    grant = world.grant(budget=Budget(1000, "USD-cents", "day"))
    world.call(grant, amount=700)
    with pytest.raises(StepUpRequired) as caught:
        world.call(grant, amount=400)
    assert caught.value.code == "budget_exceeded"
    world.call(grant, amount=300)
    world.clock.now += 86_400
    world.call(grant, amount=900)

    # The service keeps its own tally: a broker that lost count is still stopped.
    world.broker._records[grant.grant_id].state.spent = 0
    assert code_of(world.call, grant, amount=200) == "budget_exceeded"


def test_first_use_needs_confirmation_once():
    world = World()
    grant = world.grant(first_use_confirmation=True)
    with pytest.raises(StepUpRequired) as caught:
        world.call(grant)
    assert caught.value.code == "first_use"
    world.broker.confirm_first_use(grant.grant_id)
    world.call(grant)
    world.call(grant, body=b'{"title":"again"}')


def test_high_risk_action_punches_through_to_a_single_use_grant():
    world = World()
    standing = world.grant()
    with pytest.raises(InvalidGrant):
        world.grant(actions=["notes.purge"], max_risk="critical")  # never standing

    purge = b'{"confirm":"all"}'
    with pytest.raises(StepUpRequired) as caught:
        world.call(standing, action="notes.purge", body=purge)
    assert caught.value.code == "action_not_covered"

    once = world.grant(actions=["notes.purge"], max_risk="critical", single_use=True,
                       duration=300, content_digest=content_digest(purge))
    assert code_of(world.call, once, action="notes.purge",
                   body=b'{"confirm":"other"}') == "request_does_not_match_grant"
    assert world.call(once, action="notes.purge", body=purge).grant.single_use
    assert code_of(world.call, once, action="notes.purge", body=purge) == "grant_already_used"


def test_expired_grant_is_denied_on_both_sides():
    world = World()
    grant = world.grant(duration=60)
    world.clock.now += 55
    world.call(grant, action="notes.read")
    # Signed while the grant was live, received after it lapsed (proof still fresh).
    late = world.broker.authorize(grant.grant_id, action="notes.read", risk="low",
                                  method="POST", url=URL, body=BODY)
    world.clock.now += 10
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=late,
                   body=BODY) == "grant_expired"
    assert code_of(world.call, grant) == "grant_expired"


# -- revocation --------------------------------------------------------------


def test_revocation_stops_the_broker_at_once_and_reaches_the_service():
    world = World()
    grant = world.grant()
    in_flight = world.broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                                       method="POST", url=URL, body=BODY)
    event = world.broker.revoke(grant.grant_id)

    assert code_of(world.call, grant) == "grant_revoked"
    assert world.sent[-1] == (f"{SERVICE}/events", "application/secevent+jwt")
    # A request signed just before revocation is refused by the service too.
    assert code_of(world.verifier.verify_request, method="POST", url=URL, headers=in_flight,
                   body=BODY) == "grant_revoked"

    header = jwt.get_unverified_header(event)
    claims = jwt.decode(event, options={"verify_signature": False})
    assert header["typ"] == "secevent+jwt"
    assert "exp" not in claims and "sub" not in claims
    assert claims["sub_id"] == {"format": "opaque", "id": ACCOUNT}
    payload = claims["events"][tokens.EVENT_GRANT_REVOKED]
    assert payload["grant_id"] == grant.grant_id and payload["initiating_entity"] == "user"


def test_revocation_is_retried_until_the_service_is_back():
    world = World()
    grant = world.grant()
    world.service_up = False
    world.broker.revoke(grant.grant_id)
    (delivery,) = world.outbox.pending()
    assert delivery.attempts == 1 and "connection refused" in delivery.last_error

    assert world.outbox.deliver_due() == 0  # backoff not elapsed, no attempt made
    assert delivery.attempts == 1
    world.clock.now += 5
    assert world.outbox.deliver_due() == 0 and delivery.attempts == 2
    world.service_up = True
    world.clock.now += 15
    assert world.outbox.deliver_due() == 1
    assert delivery.status == "delivered" and not world.outbox.pending()
    assert world.verifier.is_revoked(ISSUER, grant.grant_id)


def test_delivery_gives_up_after_the_maximum_attempts():
    world = World()
    grant = world.grant()
    world.service_up = False
    world.broker.revoke(grant.grant_id)
    for _ in range(20):
        world.clock.now += 301
        world.outbox.deliver_due()
    (delivery,) = [d for d in world.outbox.deliveries if d.media_type.endswith("secevent+jwt")]
    assert delivery.status == "failed" and delivery.attempts == 10


def test_revocation_is_idempotent_and_survives_arriving_before_the_grant():
    world = World()
    world.service_up = False
    grant = world.grant()
    event = world.broker.revoke(grant.grant_id)
    assert world.verifier.accept_event(event) == grant.grant_id
    assert world.verifier.accept_event(event) == grant.grant_id
    # The receipt turns up late: the grant must not come back to life.
    receipt = tokens.encode_receipt(world.key, document=grant.to_document(), evidence=None,
                                    now=int(world.clock()))
    assert code_of(world.verifier.accept_grant, receipt) == "grant_revoked"


def test_events_from_strangers_or_of_the_wrong_kind_are_refused():
    world = World()
    grant = world.grant()
    stranger = SigningKey.generate()
    forged = tokens.encode_revocation(
        stranger, issuer=ISSUER, audience=SERVICE, subject=ACCOUNT, grant_id=grant.grant_id,
        grant_digest=grant.digest_hex(), initiating_entity="user", revoked_at=1, now=1)
    with pytest.raises(SignatureError) as caught:
        world.verifier.accept_event(forged)
    assert push_error(caught.value) == {"err": "invalid_key",
                                        "description": str(caught.value)}
    # A receipt is not an event, even though the same key signed it.
    assert code_of(world.verifier.accept_event,
                   world.broker.receipt(grant.grant_id)) == "token_wrong_type"
    world.call(grant)  # the grant is untouched
    with pytest.raises(Denied):
        world.broker.revoke("no-such-grant")


def test_one_broker_cannot_revoke_or_shadow_another_brokers_grant():
    world = World()
    other_key = SigningKey.generate()
    other = "https://other-broker.example"
    world.verifier.brokers[other] = BrokerTrust(KeySet.of(other_key), "other-broker.example", other)
    grant = world.grant()
    event = tokens.encode_revocation(
        other_key, issuer=other, audience=SERVICE, subject=ACCOUNT, grant_id=grant.grant_id,
        grant_digest=grant.digest_hex(), initiating_entity="admin",
        revoked_at=int(world.clock()), now=int(world.clock()))
    world.verifier.accept_event(event)
    assert not world.verifier.is_revoked(ISSUER, grant.grant_id)
    assert world.call(grant).action == "notes.write"
