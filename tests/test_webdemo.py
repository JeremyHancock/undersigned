"""Drives the browser demo's two servers over real HTTP with a software passkey."""

import importlib.util
import json
import sys
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
    sys.modules[spec.name] = module  # dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


server = _load_server()
APPS = {}  # broker URL -> the BrokerApp behind a running demo


def http(url, payload=None, headers=None, raw=None):
    """One request. Returns (status, parsed JSON body, response headers)."""
    data = raw if raw is not None else (None if payload is None else json.dumps(payload).encode())
    request = urllib.request.Request(url, data=data, headers=headers or {},
                                     method="GET" if data is None else "POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"null"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null"), exc.headers


class Visitor:
    """A browser: keeps its session cookie and owns one passkey."""

    def __init__(self, broker_url, client=None):
        self.broker_url = broker_url
        self.passkey = SoftAuthenticator()
        self.cookie = None
        self.client = client

    def call(self, path, payload=None):
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if self.client:
            headers["Fly-Client-IP"] = self.client
        status, body, response_headers = http(self.broker_url + path, payload, headers)
        if response_headers.get("Set-Cookie"):
            self.cookie = response_headers["Set-Cookie"].split(";")[0]
        return status, body

    def register(self):
        _, options = self.call("/api/register/options", {})
        credential = self.passkey.register(base64url_to_bytes(options["challenge"]),
                                           rp_id="localhost", origin=self.broker_url)
        status, registered = self.call("/api/register/verify", {"credential": credential})
        assert status == 200 and registered["credential_id"] == self.passkey.credential_id
        return registered["account"]

    def approve(self, kind, passkey=None):
        _, proposal = self.call("/api/grants/propose", {"kind": kind})
        assertion = (passkey or self.passkey).assertion(
            base64url_to_bytes(proposal["challenge"]), rp_id="localhost",
            origin=self.broker_url)
        status, activated = self.call("/api/grants/activate",
                                      {"grant_id": proposal["grant_id"], "credential": assertion})
        return proposal["grant_id"], status, activated

    def agent(self, grant_id, scenario):
        status, result = self.call("/api/agent", {"grant_id": grant_id, "scenario": scenario})
        assert status == 200, result
        return result

    def notes(self):
        return self.call("/api/service")[1]["notes"]


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture()
def demo(request):
    options = getattr(request, "param", {})
    clock = Clock()
    servers, broker_url, service_url = server.start(0, 0, clock=clock, **options)
    APPS[broker_url] = servers[0].app
    yield broker_url, service_url, clock
    del APPS[broker_url]
    for running in servers:
        running.shutdown()
        running.server_close()


def test_full_flow_over_http(demo):
    broker_url, _, _ = demo
    visitor = Visitor(broker_url)
    visitor.register()
    standing, status, activated = visitor.approve("standing")
    assert status == 200 and activated["delivered_to_service"] is True

    # Inside the envelope: three writes a day.
    for number in (1, 2, 3):
        result = visitor.agent(standing, "write")
        assert result["outcome"] == "verified" and result["by"] == "service"
        assert result["service_response"]["human_verified"] is True
        assert len(result["service_response"]["notes"]) == number
        assert {"Content-Digest", "Grant-Proof", "Signature-Input", "Signature"} <= set(
            result["headers"])
    fourth = visitor.agent(standing, "write")
    assert (fourth["outcome"], fourth["code"]) == ("step_up", "budget_exceeded")

    # A body that differs from the one signed is refused by the service.
    tampered = visitor.agent(standing, "tamper")
    assert (tampered["outcome"], tampered["by"], tampered["code"]) == (
        "refused", "service", "digest_mismatch")
    assert tampered["headers"] == {}

    # A critical action punches through to a single-use grant.
    blocked = visitor.agent(standing, "purge")
    assert (blocked["outcome"], blocked["code"]) == ("step_up", "action_not_covered")
    once, status, _ = visitor.approve("purge")
    assert status == 200
    purged = visitor.agent(once, "purge")
    assert purged["outcome"] == "verified" and purged["service_response"]["notes"] == []
    assert purged["service_response"]["single_use_grant"] is True
    again = visitor.agent(once, "purge")
    assert (again["outcome"], again["code"]) == ("refused", "grant_already_used")

    # Revocation stops the broker and reaches the service.
    status, revoked = visitor.call("/api/grants/revoke", {})
    assert status == 200 and revoked == {"revoked": 2, "delivered_to_service": True}
    after = visitor.agent(standing, "read")
    assert (after["outcome"], after["by"], after["code"]) == ("refused", "broker", "grant_revoked")


def test_service_refuses_requests_that_bypass_the_broker(demo):
    broker_url, service_url, _ = demo
    status, body, _ = http(f"{service_url}/v1/notes.write", {"title": "sneaky"})
    assert (status, body["error"]) == (403, "proof_missing")
    for path in ("/link", "/unlink"):
        status, _, _ = http(service_url + path, {"subject": "acct_x", "credential_id": "x",
                                                 "public_key": "eA"})
        assert status == 401
    assert http(f"{service_url}/audit?subject=acct_x")[0] == 401
    status, body, _ = http(f"{service_url}/grants", {"not": "a token"})
    assert status == 400 and body["err"] == "invalid_request"


def test_query_string_is_part_of_what_is_signed(demo):
    broker_url, service_url, _ = demo
    visitor = Visitor(broker_url)
    visitor.register()
    standing, _, _ = visitor.approve("standing")
    headers = visitor.agent(standing, "write")["headers"]
    # Validly signed headers, sent to the same path with a query string added.
    status, body, _ = http(f"{service_url}/v1/notes.write?owner=someone-else",
                           {"title": "Note 1"}, headers)
    assert (status, body["error"]) == (403, "invalid_signature")


def test_grant_signed_by_a_different_passkey_is_rejected(demo):
    broker_url, _, _ = demo
    visitor = Visitor(broker_url)
    visitor.register()
    grant_id, status, _ = visitor.approve("standing", passkey=SoftAuthenticator())
    assert status == 400
    result = visitor.agent(grant_id, "read")
    assert (result["outcome"], result["code"]) == ("refused", "grant_not_active")


def test_visitors_are_isolated_from_each_other(demo):
    broker_url, _, _ = demo
    alice, bob = Visitor(broker_url), Visitor(broker_url)
    assert alice.register() != bob.register()
    alices, _, _ = alice.approve("standing")
    bobs, _, _ = bob.approve("standing")
    alice.agent(alices, "write")
    assert alice.notes() == ["Note 1"] and bob.notes() == []

    # Bob cannot act under Alice's grant, and his revoking does not touch hers.
    status, body = bob.call("/api/agent", {"grant_id": alices, "scenario": "write"})
    assert status == 400 and "no such grant" in body["message"]
    spare, _, _ = bob.approve("standing")
    assert bob.call("/api/grants/revoke", {})[1]["revoked"] == 2
    assert bob.agent(spare, "read")["code"] == "grant_revoked"
    assert alice.agent(alices, "write")["outcome"] == "verified"
    bobs, _, _ = bob.approve("standing")
    assert bob.agent(bobs, "write")["service_response"]["notes"] == ["Note 1"]

    # One session, one passkey.
    _, options = alice.call("/api/register/options", {})
    again = alice.passkey.register(base64url_to_bytes(options["challenge"]),
                                   rp_id="localhost", origin=broker_url)
    assert alice.call("/api/register/verify", {"credential": again})[0] == 400


def test_idle_sessions_are_forgotten_everywhere(demo):
    broker_url, service_url, clock = demo
    visitor = Visitor(broker_url)
    account = visitor.register()
    standing, _, _ = visitor.approve("standing")
    visitor.agent(standing, "write")
    assert visitor.notes() == ["Note 1"]

    clock.now += 31 * 60
    newcomer = Visitor(broker_url)
    newcomer.register()  # any request triggers the sweep

    # The old cookie now opens a fresh, empty session...
    old_cookie = visitor.cookie
    status, body = visitor.call("/api/agent", {"grant_id": standing, "scenario": "read"})
    assert status == 400 and visitor.cookie != old_cookie
    assert visitor.notes() == []
    # ...and the service has dropped the account, its notes and its evidence.
    app = APPS[broker_url]
    assert account not in {s.subject for s in app.sessions.values()}
    _, state, _ = http(f"{service_url}/audit?subject={account}",
                       headers={"Authorization": f"Bearer {app.link_secret}"})
    assert state["notes"] == [] and state["accepted"] == []
    assert app.broker._records.get(standing) is None
    assert app.broker.outbox.deliveries == []


@pytest.mark.parametrize("demo", [dict(
    trust_proxy=True,
    limits=server.Limits(max_sessions=3, max_sessions_per_client=2, requests_per_minute=8),
)], indirect=True)
def test_capacity_and_rate_limits(demo):
    broker_url, _, clock = demo
    first, second, third = (Visitor(broker_url, client="203.0.113.5") for _ in range(3))
    assert first.call("/api/register/options", {})[0] == 200
    assert second.call("/api/register/options", {})[0] == 200
    status, body = third.call("/api/register/options", {})  # third session from one address
    assert (status, body["error"]) == (503, "busy")

    other = Visitor(broker_url, client="198.51.100.7")
    assert other.call("/api/register/options", {})[0] == 200
    full = Visitor(broker_url, client="192.0.2.9")  # fourth session overall
    assert full.call("/api/register/options", {})[0] == 503

    for _ in range(7):
        other.call("/api/service")
    status, body = other.call("/api/service")
    assert (status, body["error"]) == (429, "rate_limited")
    clock.now += 61
    assert other.call("/api/service")[0] == 200


def test_page_and_oversized_requests(demo):
    broker_url, _, _ = demo
    with urllib.request.urlopen(broker_url + "/") as response:
        assert response.status == 200
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert b"undersigned" in response.read()
    assert http(broker_url + "/healthz")[1] == {"ok": True}
    status, body, _ = http(broker_url + "/api/agent", raw=b"x" * (server.MAX_BODY + 1))
    assert (status, body["error"]) == (413, "too_large")


def test_revoking_also_ends_an_unused_single_use_approval(demo):
    """Found by hand on the live demo: approve a delete, revoke, then delete."""
    broker_url, _, _ = demo
    visitor = Visitor(broker_url)
    visitor.register()
    standing, _, _ = visitor.approve("standing")
    visitor.agent(standing, "write")
    once, _, _ = visitor.approve("purge")  # approved but not yet used

    status, revoked = visitor.call("/api/grants/revoke", {})
    assert status == 200 and revoked == {"revoked": 2, "delivered_to_service": True}
    purge = visitor.agent(once, "purge")
    assert (purge["outcome"], purge["by"], purge["code"]) == ("refused", "broker", "grant_revoked")
    assert visitor.notes() == ["Note 1"]
