import pytest

from undersigned import jcs
from undersigned.errors import EvidenceError, InvalidGrant
from undersigned.evidence import HumanEvidence, verify_evidence
from undersigned.grant import Budget, Grant
from undersigned.policy import ALLOW, DENY, STEP_UP, GrantState, evaluate, record_use
from undersigned.testing import SoftAuthenticator

RP_ID = "broker.example"
ORIGIN = "https://broker.example"
T0 = 1_800_000_000


def standing(**overrides) -> Grant:
    fields = dict(
        issuer="https://broker.example",
        audience="https://notes.example",
        subject="acct_42",
        actions=("notes.read", "notes.write"),
        issued_at=T0,
        expires_at=T0 + 30 * 86_400,
        max_risk="medium",
    )
    fields.update(overrides)
    return Grant(**fields)


# -- canonicalization ------------------------------------------------------


def test_jcs_sorts_keys_and_strips_whitespace():
    assert jcs.canonicalize({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_jcs_escapes_like_ecmascript():
    assert jcs.canonicalize("a\n\u0001\"\\é") == '"a\\n\\u0001\\"\\\\é"'.encode("utf-8")


def test_jcs_sorts_by_utf16_code_units():
    # U+1F600 encodes as surrogates (0xD83D...), which sort before U+FF5E.
    assert jcs.canonicalize({"～": 1, "\U0001f600": 2}).startswith('{"\U0001f600"'.encode())


@pytest.mark.parametrize("bad", [1.5, {1: "x"}, 2**53, object()])
def test_jcs_rejects_unsupported_values(bad):
    with pytest.raises(ValueError):
        jcs.canonicalize(bad)


# -- grant document --------------------------------------------------------


def test_grant_round_trips_through_its_document():
    grant = standing(budget=Budget(5000, "USD-cents", "week"), first_use_confirmation=True)
    again = Grant.from_document(grant.to_document())
    assert again == grant
    assert again.digest() == grant.digest()


def test_digest_changes_when_the_envelope_changes():
    assert standing(grant_id="g").digest() != standing(grant_id="g", max_risk="low").digest()


def test_document_uses_rar_shape():
    detail = standing().to_document()["authorization_details"][0]
    assert detail["type"] and detail["locations"] == ["https://notes.example"]
    assert detail["actions"] == ["notes.read", "notes.write"]


def test_unknown_fields_are_rejected():
    document = standing().to_document()
    document["authorization_details"][0]["extra"] = True
    with pytest.raises(InvalidGrant):
        Grant.from_document(document)


def test_locations_must_match_audience():
    document = standing().to_document()
    document["authorization_details"][0]["locations"] = ["https://evil.example"]
    with pytest.raises(InvalidGrant):
        Grant.from_document(document)


def test_standing_grant_cannot_cover_high_risk():
    with pytest.raises(InvalidGrant):
        standing(max_risk="high")


def test_single_use_grant_can_cover_critical_but_only_one_action():
    Grant(**{**standing().__dict__, "actions": ("notes.purge",), "max_risk": "critical",
             "single_use": True})
    with pytest.raises(InvalidGrant):
        standing(single_use=True)


# -- envelope evaluation ---------------------------------------------------


def decide(grant, state=None, **kw):
    kw.setdefault("action", "notes.write")
    kw.setdefault("risk", "medium")
    kw.setdefault("now", T0 + 10)
    return evaluate(grant, state or GrantState(), **kw)


def test_allows_action_inside_envelope():
    assert decide(standing()).outcome == ALLOW


def test_uncovered_action_and_high_risk_step_up():
    assert decide(standing(), action="notes.delete").reason == "action_not_covered"
    decision = decide(standing(), risk="high")
    assert (decision.outcome, decision.reason) == (STEP_UP, "risk_exceeds_grant")


def test_expired_and_revoked_are_denied():
    grant = standing()
    assert decide(grant, now=grant.expires_at).reason == "grant_expired"
    assert decide(grant, GrantState(revoked=True)).outcome == DENY
    assert decide(grant, now=T0 - 5).reason == "grant_not_yet_valid"


def test_first_use_steps_up_until_confirmed():
    grant = standing(first_use_confirmation=True)
    assert decide(grant).reason == "first_use"
    assert decide(grant, GrantState(first_use_confirmed=True)).outcome == ALLOW
    assert decide(grant, enforce_first_use=False).outcome == ALLOW


def test_budget_is_enforced_and_resets_each_period():
    grant = standing(budget=Budget(1000, "USD-cents", "day"))
    state = GrantState()
    assert decide(grant, state, amount=600).outcome == ALLOW
    record_use(grant, state, amount=600, now=T0 + 10)
    assert decide(grant, state, amount=500).reason == "budget_exceeded"
    assert decide(grant, state, amount=400).outcome == ALLOW
    assert decide(grant, state, amount=500, now=T0 + 86_400 + 1).outcome == ALLOW


def test_negative_amount_is_denied():
    assert decide(standing(), amount=-1).reason == "invalid_amount"


def test_single_use_grant_is_spent_after_one_use():
    grant = Grant(
        issuer="https://broker.example", audience="https://notes.example", subject="acct_42",
        actions=("notes.purge",), issued_at=T0, expires_at=T0 + 300, max_risk="critical",
        single_use=True, content_digest="sha-256=:abc=:",
    )
    state = GrantState()
    kw = dict(action="notes.purge", risk="critical", content_digest="sha-256=:abc=:")
    assert decide(grant, state, **kw).outcome == ALLOW
    assert decide(grant, state, **{**kw, "content_digest": "sha-256=:zzz=:"}).reason == (
        "request_does_not_match_grant"
    )
    record_use(grant, state, now=T0 + 10)
    assert decide(grant, state, **kw).reason == "grant_already_used"


# -- human evidence --------------------------------------------------------


def test_assertion_over_grant_digest_verifies():
    passkey = SoftAuthenticator()
    grant = standing()
    evidence = passkey.sign(grant.digest(), rp_id=RP_ID, origin=ORIGIN)
    restored = HumanEvidence.from_dict(evidence.to_dict())
    verify_evidence(restored, challenge=grant.digest(), rp_id=RP_ID, origin=ORIGIN,
                    credential_public_key=passkey.cose_public_key)


def test_assertion_does_not_verify_for_a_different_grant():
    passkey = SoftAuthenticator()
    evidence = passkey.sign(standing().digest(), rp_id=RP_ID, origin=ORIGIN)
    widened = standing(actions=("notes.read", "notes.write", "notes.delete"))
    with pytest.raises(EvidenceError):
        verify_evidence(evidence, challenge=widened.digest(), rp_id=RP_ID, origin=ORIGIN,
                        credential_public_key=passkey.cose_public_key)


def test_assertion_from_another_passkey_or_origin_fails():
    passkey, other = SoftAuthenticator(), SoftAuthenticator()
    grant = standing()
    evidence = passkey.sign(grant.digest(), rp_id=RP_ID, origin=ORIGIN)
    with pytest.raises(EvidenceError):
        verify_evidence(evidence, challenge=grant.digest(), rp_id=RP_ID, origin=ORIGIN,
                        credential_public_key=other.cose_public_key)
    with pytest.raises(EvidenceError):
        verify_evidence(evidence, challenge=grant.digest(), rp_id=RP_ID,
                        origin="https://phish.example",
                        credential_public_key=passkey.cose_public_key)


def test_assertion_without_user_verification_fails():
    passkey = SoftAuthenticator()
    grant = standing()
    evidence = passkey.sign(grant.digest(), rp_id=RP_ID, origin=ORIGIN, user_verified=False)
    with pytest.raises(EvidenceError):
        verify_evidence(evidence, challenge=grant.digest(), rp_id=RP_ID, origin=ORIGIN,
                        credential_public_key=passkey.cose_public_key)
