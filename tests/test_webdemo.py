"""Drives the browser demo's two servers over real HTTP with a software passkey."""

import importlib.util
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from webauthn.helpers import base64url_to_bytes

from undersigned.testing import SoftAuthenticator

SERVER = Path(__file__).parent.parent / "examples" / "webdemo" / "server.py"


def _load_server():
    spec = importlib.util.spec_from_file_location("webdemo_server", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def call(url, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers=headers or {},
                                     method="GET" if payload is None else "POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


@pytest.fixture()
def demo():
    servers, broker_url, service_url = _load_server().start(0, 0)
    yield broker_url, service_url
    for server in servers:
        server.shutdown()
        server.server_close()


def approve(broker_url, passkey, kind):
    _, proposal = call(f"{broker_url}/api/grants/propose", {"kind": kind})
    assertion = passkey.assertion(base64url_to_bytes(proposal["challenge"]),
                                  rp_id="localhost", origin=broker_url)
    status, activated = call(f"{broker_url}/api/grants/activate",
                             {"grant_id": proposal["grant_id"], "credential": assertion})
    assert status == 200 and activated["delivered_to_service"] is True
    return proposal["grant_id"]


def agent(broker_url, grant_id, scenario):
    status, result = call(f"{broker_url}/api/agent", {"grant_id": grant_id, "scenario": scenario})
    assert status == 200
    return result


def test_full_flow_over_http(demo):
    broker_url, service_url = demo
    passkey = SoftAuthenticator()

    # Register a passkey with the broker; the broker links the account at the service.
    _, options = call(f"{broker_url}/api/register/options", {})
    credential = passkey.register(base64url_to_bytes(options["challenge"]),
                                  rp_id="localhost", origin=broker_url)
    status, registered = call(f"{broker_url}/api/register/verify", {"credential": credential})
    assert status == 200 and registered["credential_id"] == passkey.credential_id

    standing = approve(broker_url, passkey, "standing")

    # Inside the envelope: three writes a day.
    for number in (1, 2, 3):
        result = agent(broker_url, standing, "write")
        assert result["outcome"] == "verified" and result["by"] == "service"
        assert result["service_response"]["human_verified"] is True
        assert len(result["service_response"]["notes"]) == number
        assert {"Content-Digest", "Grant-Proof", "Signature-Input", "Signature"} <= set(
            result["headers"])
    fourth = agent(broker_url, standing, "write")
    assert (fourth["outcome"], fourth["code"]) == ("step_up", "budget_exceeded")

    # A body that differs from the one signed is refused by the service.
    tampered = agent(broker_url, standing, "tamper")
    assert (tampered["outcome"], tampered["by"], tampered["code"]) == (
        "refused", "service", "digest_mismatch")

    # A critical action punches through to a single-use grant.
    blocked = agent(broker_url, standing, "purge")
    assert (blocked["outcome"], blocked["code"]) == ("step_up", "action_not_covered")
    once = approve(broker_url, passkey, "purge")
    purged = agent(broker_url, once, "purge")
    assert purged["outcome"] == "verified" and purged["service_response"]["notes"] == []
    assert purged["service_response"]["single_use_grant"] is True
    again = agent(broker_url, once, "purge")
    assert (again["outcome"], again["code"]) == ("refused", "grant_already_used")

    # Revocation stops the broker and reaches the service.
    status, revoked = call(f"{broker_url}/api/grants/revoke", {"grant_id": standing})
    assert status == 200 and revoked["delivered_to_service"] is True
    after = agent(broker_url, standing, "read")
    assert (after["outcome"], after["by"], after["code"]) == ("refused", "broker", "grant_revoked")

    _, state = call(f"{broker_url}/api/service")
    results = [entry["result"] for entry in state["audit"]]
    assert results == ["verified", "verified", "verified", "refused", "verified"]
    assert state["audit"][0]["record"]["grant_id"] == standing


def test_service_refuses_requests_that_bypass_the_broker(demo):
    broker_url, service_url = demo
    status, body = call(f"{service_url}/v1/notes.write", {"title": "sneaky"})
    assert (status, body["error"]) == (403, "proof_missing")
    status, _ = call(f"{service_url}/link",
                     {"subject": "acct_demo", "credential_id": "x", "public_key": "eA"})
    assert status == 401
    status, body = call(f"{service_url}/grants", {"not": "a token"})
    assert status == 400 and body["err"] == "invalid_request"


def test_grant_signed_by_an_unregistered_passkey_is_rejected(demo):
    broker_url, _ = demo
    passkey, stranger = SoftAuthenticator(), SoftAuthenticator()
    _, options = call(f"{broker_url}/api/register/options", {})
    credential = passkey.register(base64url_to_bytes(options["challenge"]),
                                  rp_id="localhost", origin=broker_url)
    call(f"{broker_url}/api/register/verify", {"credential": credential})
    _, proposal = call(f"{broker_url}/api/grants/propose", {"kind": "standing"})
    forged = stranger.assertion(base64url_to_bytes(proposal["challenge"]),
                                rp_id="localhost", origin=broker_url)
    status, body = call(f"{broker_url}/api/grants/activate",
                        {"grant_id": proposal["grant_id"], "credential": forged})
    assert status == 400
    result = agent(broker_url, proposal["grant_id"], "read")
    assert (result["outcome"], result["code"]) == ("refused", "grant_not_active")


def test_query_string_is_part_of_what_is_signed(demo):
    broker_url, service_url = demo
    passkey = SoftAuthenticator()
    _, options = call(f"{broker_url}/api/register/options", {})
    credential = passkey.register(base64url_to_bytes(options["challenge"]),
                                  rp_id="localhost", origin=broker_url)
    call(f"{broker_url}/api/register/verify", {"credential": credential})
    standing = approve(broker_url, passkey, "standing")
    headers = agent(broker_url, standing, "write")["headers"]
    # Fresh, validly signed headers, replayed against the same path with a query added.
    status, body = call(f"{service_url}/v1/notes.write?owner=someone-else",
                        {"title": "Note 1"}, headers)
    assert (status, body["error"]) == (403, "invalid_signature")
    refused = agent(broker_url, standing, "tamper")
    assert refused["outcome"] == "refused" and refused["headers"] == {}
