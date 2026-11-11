"""Broker and service wired together the way an integration would be."""

import json

import jwt
import pytest

from undersigned import httpsig, tokens
from undersigned.broker import SIGNATURE_TAG, SIGNED_COMPONENTS, Broker, ServiceEndpoints
from undersigned.errors import (
    Denied, EvidenceError, InvalidGrant, SignatureError, StepUpRequired, UndersignedError,
    UnknownGrant,
)
from undersigned.grant import Budget, PinnedRequest
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


def cost_of(action, body):
    """A write costs whatever its body says; everything else is free."""
    return json.loads(body).get("cost", 0) if action == "notes.write" else 0


def costing(amount):
    return json.dumps({"title": "x", "cost": amount}).encode()


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class World:
    """One broker, one service, one human with a passkey."""

    def __init__(self, pin=True, max_attempts=None, **verifier_options):
        self.clock = Clock()
        self.key = SigningKey.generate()
        self.sent = []
        self.service_up = True
        self.outbox = Outbox(self._send, clock=self.clock, max_attempts=max_attempts)
        self.broker = Broker(
            issuer=ISSUER, key=self.key, rp_id=RP_ID, origin=ISSUER, clock=self.clock,
            risk_of=RISKS.get, cost_of=cost_of, outbox=self.outbox,
            services={SERVICE: ServiceEndpoints(f"{SERVICE}/grants", f"{SERVICE}/events")},
        )
        self.verifier = Verifier(
            audience=SERVICE,
            brokers={ISSUER: BrokerTrust(KeySet.from_jwks(self.broker.jwks()), RP_ID, ISSUER)},
            risk_of=RISKS.get, cost_of=cost_of, clock=self.clock, **verifier_options,
        )
        self.passkey = SoftAuthenticator()
        if pin:
            self.verifier.pin_passkey(ISSUER, ACCOUNT, self.passkey.credential_id,
                                      self.passkey.cose_public_key)

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

    def sign(self, grant, action="notes.write", body=BODY, method="POST", url=URL):
        return self.broker.authorize(grant.grant_id, action=action, method=method, url=url,
                                     body=body)

    def receive(self, headers, action="notes.write", body=BODY, method="POST", url=URL):
        return self.verifier.verify_request(action=action, method=method, url=url,
                                            headers=headers, body=body)

    def call(self, grant, action="notes.write", body=BODY):
        return self.receive(self.sign(grant, action, body), action, body)

    def forge(self, grant, *, action, amount=0, body=BODY, method="POST", url=URL):
        """Headers from someone holding the broker's key but ignoring its rules."""
        now = int(self.clock())
        proof = tokens.encode_proof(
            self.key, issuer=ISSUER, audience=SERVICE, subject=ACCOUNT,
            grant_id=grant.grant_id, grant_digest=grant.digest_hex(), action=action,
            amount=amount, now=now, ttl=30)
        headers = {"Content-Digest": content_digest(body), "Grant-Proof": proof}
        headers.update(httpsig.sign_request(
            self.key, method=method, url=url, headers=headers, components=SIGNED_COMPONENTS,
            created=now, expires=now + 30, tag=SIGNATURE_TAG))
        return headers


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
    headers = world.sign(grant, "notes.read")
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
    headers = world.sign(grant)
    assert code_of(world.receive, headers, body=b'{"title":"evil"}') == "digest_mismatch"
    assert code_of(world.receive, headers, method="DELETE") == "invalid_signature"
    assert code_of(world.receive, headers, url=URL + "?all=1") == "invalid_signature"
    world.receive(headers)  # the untouched request still goes through


def test_replayed_request_is_refused():
    world = World()
    headers = world.sign(world.grant())
    world.receive(headers)
    assert code_of(world.receive, headers) == "proof_replayed"


def test_stale_request_is_refused():
    world = World()
    headers = world.sign(world.grant())
    world.clock.now += 120
    assert code_of(world.receive, headers) == "signature_expired"


def test_request_without_proof_or_from_unknown_broker_is_refused():
    world, stranger = World(), World()
    assert code_of(world.receive, {}) == "proof_missing"
    # Same issuer name, different key: the service does not hold it.
    assert code_of(world.receive, stranger.sign(stranger.grant())) == "unknown_key"


def test_unknown_grant_can_be_recovered_by_resending_the_receipt():
    world = World()
    world.service_up = False
    grant = world.grant()
    assert code_of(world.call, grant) == UnknownGrant.code
    world.verifier.accept_grant(world.broker.receipt(grant.grant_id))
    assert world.call(grant).action == "notes.write"


def test_proof_for_one_action_cannot_be_used_at_another_endpoint():
    world = World()
    grant = world.grant()
    headers = world.sign(grant, "notes.read")
    assert code_of(world.receive, headers, action="notes.purge") == "action_mismatch"
    world.receive(headers, action="notes.read")  # refusal did not burn the proof


def test_broker_will_not_sign_for_an_action_it_does_not_know():
    world = World()
    assert code_of(world.sign, world.grant(), "notes.unheard-of") == "unknown_action"


# -- the service checks the envelope itself ----------------------------------
# In these the broker's key is used without the broker's rules, as it would be
# by a compromised broker or a thief of its signing key.


def test_service_rejects_a_proof_the_grant_does_not_cover():
    world = World()
    grant = world.grant(actions=["notes.read"], max_risk="low")
    headers = world.forge(grant, action="notes.purge")
    assert code_of(world.receive, headers, action="notes.purge") == "action_not_covered"


def test_service_uses_its_own_risk_rating():
    world = World()
    grant = world.grant()
    world.broker._risk_of = lambda action: "low"  # the broker under-rates everything
    headers = world.sign(grant)
    world.verifier._risk_of = {"notes.write": "high"}.get
    assert code_of(world.receive, headers) == "risk_exceeds_grant"


def test_service_computes_the_cost_itself():
    world = World()
    grant = world.grant(budget=Budget(1000, "USD-cents", "day"))
    body = costing(700)
    understated = world.forge(grant, action="notes.write", amount=0, body=body)
    assert code_of(world.receive, understated, body=body) == "amount_mismatch"
    for _ in range(2):
        honest = world.forge(grant, action="notes.write", amount=700, body=body)
        outcome = None
        try:
            world.receive(honest, body=body)
        except Denied as exc:
            outcome = exc.code
    assert outcome == "budget_exceeded"  # the second 700 would pass 1000


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


def test_a_passkey_pinned_for_one_broker_does_not_count_for_another():
    world = World(pin=False)
    world.verifier.pin_passkey("https://other-broker.example", ACCOUNT,
                               world.passkey.credential_id, world.passkey.cose_public_key)
    world.service_up = False
    grant = world.grant()
    assert code_of(world.verifier.accept_grant,
                   world.broker.receipt(grant.grant_id)) == "unknown_passkey"


def test_broker_attested_grants_are_refused_unless_the_service_opts_in():
    strict = World()
    strict.service_up = False
    unsigned = strict.grant(sign=False)
    assert code_of(strict.verifier.accept_grant,
                   strict.broker.receipt(unsigned.grant_id)) == "human_evidence_required"
    lenient = World(require_human_evidence=False)
    assert lenient.call(lenient.grant(sign=False)).human_verified is False


def test_broker_will_not_activate_a_grant_with_bad_evidence():
    world = World()
    grant = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.read"],
                                 duration=3600)
    other = world.broker.propose(audience=SERVICE, subject=ACCOUNT, actions=["notes.write"],
                                 duration=3600, max_risk="medium")
    evidence = world.passkey.sign(other.digest(), rp_id=RP_ID, origin=ISSUER)
    assert code_of(world.broker.activate, grant.grant_id, evidence,
                   credential_public_key=world.passkey.cose_public_key) == EvidenceError.code
    assert code_of(world.call, grant, "notes.read") == "grant_not_active"


def test_an_active_grant_cannot_be_activated_again_without_its_evidence():
    world = World()
    grant = world.grant()
    assert code_of(world.broker.activate, grant.grant_id) == "grant_already_active"
    claims = jwt.decode(world.broker.receipt(grant.grant_id),
                        options={"verify_signature": False})
    assert claims["evidence"]["type"] == "webauthn"


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
    world.call(grant, body=costing(700))
    with pytest.raises(StepUpRequired) as caught:
        world.call(grant, body=costing(400))
    assert caught.value.code == "budget_exceeded"
    world.call(grant, body=costing(300))
    world.clock.now += 86_400
    world.call(grant, body=costing(900))

    # The service keeps its own tally: a broker that lost count is still stopped.
    world.broker._records[grant.grant_id].state.spent = 0
    assert code_of(world.call, grant, body=costing(200)) == "budget_exceeded"


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
        world.call(standing, "notes.purge", purge)
    assert caught.value.code == "action_not_covered"

    once = world.grant(actions=["notes.purge"], max_risk="critical", single_use=True,
                       duration=300, request=PinnedRequest.of("POST", URL, purge))
    # The agent cannot get it signed for any other body, method or URL...
    mismatch = "request_does_not_match_grant"
    assert code_of(world.sign, once, "notes.purge", b'{"confirm":"other"}') == mismatch
    assert code_of(world.sign, once, "notes.purge", purge, method="DELETE") == mismatch
    assert code_of(world.sign, once, "notes.purge", purge, url=URL + "/other") == mismatch
    # ...and the service refuses one even when the broker's key signs it.
    elsewhere = world.forge(once, action="notes.purge", body=purge, url=URL + "/other")
    assert code_of(world.receive, elsewhere, action="notes.purge", body=purge,
                   url=URL + "/other") == mismatch

    assert world.call(once, "notes.purge", purge).grant.single_use
    assert code_of(world.call, once, "notes.purge", purge) == "grant_already_used"
    replay = world.forge(once, action="notes.purge", body=purge)
    assert code_of(world.receive, replay, action="notes.purge",
                   body=purge) == "grant_already_used"


def test_expired_grant_is_denied_on_both_sides():
    world = World()
    grant = world.grant(duration=60)
    world.clock.now += 55
    world.call(grant, "notes.read")
    # Signed while the grant was live, received after it lapsed (proof still fresh).
    late = world.sign(grant, "notes.read")
    world.clock.now += 10
    assert code_of(world.receive, late, action="notes.read") == "grant_expired"
    assert code_of(world.call, grant) == "grant_expired"


# -- revocation --------------------------------------------------------------


def test_revocation_stops_the_broker_at_once_and_reaches_the_service():
    world = World()
    grant = world.grant()
    in_flight = world.sign(grant)
    event = world.broker.revoke(grant.grant_id)

    assert code_of(world.call, grant) == "grant_revoked"
    assert code_of(world.broker.receipt, grant.grant_id) == "grant_revoked"
    assert world.sent[-1] == (f"{SERVICE}/events", "application/secevent+jwt")
    # A request signed just before revocation is refused by the service too.
    assert code_of(world.receive, in_flight) == "grant_revoked"

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
    for _ in range(30):  # a long outage: it keeps trying
        world.clock.now += 301
        world.outbox.deliver_due()
    assert delivery.status == "queued" and delivery.attempts == 32
    world.service_up = True
    world.clock.now += 301
    assert world.outbox.deliver_due() == 1
    assert delivery.status == "delivered" and not world.outbox.pending()
    assert world.verifier.is_revoked(ISSUER, grant.grant_id)


def test_delivery_can_be_capped():
    world = World(max_attempts=3)
    world.service_up = False
    grant = world.grant()  # the receipt delivery fails too
    for _ in range(10):
        world.clock.now += 301
        world.outbox.deliver_due()
    (delivery,) = world.outbox.deliveries
    assert delivery.status == "failed" and delivery.attempts == 3
    assert grant.grant_id


def test_revocation_is_idempotent_and_survives_arriving_before_the_grant():
    world = World()
    world.service_up = False
    grant = world.grant()
    receipt = world.broker.receipt(grant.grant_id)
    event = world.broker.revoke(grant.grant_id)
    assert world.verifier.accept_event(event) == grant.grant_id
    assert world.verifier.accept_event(event) == grant.grant_id
    # The receipt turns up late: the grant must not come back to life.
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
