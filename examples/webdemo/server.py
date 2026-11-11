"""A browser demo with a real passkey and real HTTP between two servers.

    python examples/webdemo/server.py

starts a broker (http://localhost:8000, with the page you click through) and a
notes service (http://localhost:8001). The two only talk over HTTP. You create
a passkey, sign a standing grant with it, and watch an agent act inside and
outside the envelope.

It is a single-user local demo built on the standard library: one account, no
sessions, state in memory.
"""

from __future__ import annotations

import argparse
import json
import secrets
import threading
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from undersigned import (
    Broker, BrokerTrust, Budget, Denied, HumanEvidence, KeySet, Outbox, PinnedRequest,
    ServiceEndpoints, SigningKey, StepUpRequired, UndersignedError, UnknownGrant, Verifier,
    push_error,
)

ACCOUNT = "acct_demo"
RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}
PURGE_BODY = b'{"confirm":"delete all notes"}'


def cost_of(action: str, _body: bytes) -> int:
    """What an action draws from a budget. Broker and service each apply it."""
    return 1 if action == "notes.write" else 0

PAGE = Path(__file__).with_name("index.html")

Response = tuple[int, str, bytes]


def as_json(status: int, payload) -> Response:
    return status, "application/json", json.dumps(payload).encode("utf-8")


def http_post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def http_get_json(url: str):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read())


# -- the notes service -------------------------------------------------------


class NotesService:
    """The API being called. It knows the broker only by its URL and its keys."""

    def __init__(self, public_url: str, broker_url: str, link_secret: str):
        self.public_url = public_url
        self.broker_url = broker_url
        self.link_secret = link_secret
        self.notes: list[str] = []
        self.audit: list[dict] = []
        self._verifier: Verifier | None = None
        self._lock = threading.Lock()

    @property
    def verifier(self) -> Verifier:
        if self._verifier is None:
            # Fetch the broker's public keys the way any service would.
            keys = KeySet.from_jwks(http_get_json(self.broker_url + "/.well-known/jwks.json"))
            trust = BrokerTrust(keys, rp_id=urlsplit(self.broker_url).hostname,
                                origin=self.broker_url)
            self._verifier = Verifier(audience=self.public_url,
                                      brokers={self.broker_url: trust}, risk_of=RISKS.get,
                                      cost_of=cost_of)
        return self._verifier

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Response:
        path = target.split("?")[0]
        with self._lock:
            if method == "GET" and path == "/audit":
                return as_json(200, {"notes": self.notes, "audit": self.audit})
            if method != "POST":
                return as_json(404, {"error": "not_found"})
            if path == "/link":
                return self._link(headers, body)
            if path == "/grants":
                try:
                    grant = self.verifier.accept_grant(body.decode("ascii"))
                except (UndersignedError, UnicodeDecodeError) as exc:
                    return as_json(400, push_error(exc))
                return as_json(201, {"grant_id": grant.grant_id})
            if path == "/events":
                try:
                    self.verifier.accept_event(body.decode("ascii"))
                except (UndersignedError, UnicodeDecodeError) as exc:
                    return as_json(400, push_error(exc))
                return 202, "application/json", b""
            if path.startswith("/v1/"):
                return self._action(path.removeprefix("/v1/"), target, headers, body)
            return as_json(404, {"error": "not_found"})

    def _link(self, headers: dict[str, str], body: bytes) -> Response:
        """Account linking: the one moment the service trusts the broker's word."""
        if not secrets.compare_digest(headers.get("authorization", ""),
                                      f"Bearer {self.link_secret}"):
            return as_json(401, {"error": "unauthorized"})
        data = json.loads(body)
        self.verifier.pin_passkey(self.broker_url, data["subject"], data["credential_id"],
                                  base64url_to_bytes(data["public_key"]))
        return as_json(200, {"linked": data["subject"]})

    def _action(self, action: str, target: str, headers: dict[str, str],
                body: bytes) -> Response:
        path = target.split("?")[0]
        try:
            # The action comes from this service's routing, and the URL is the
            # full request target, query string included.
            verified = self.verifier.verify_request(
                action=action, method="POST", url=self.public_url + target, headers=headers,
                body=body)
        except UnknownGrant as exc:
            return as_json(409, {"error": exc.code, "message": str(exc)})
        except UndersignedError as exc:
            self.audit.append({"path": path, "result": "refused", "code": exc.code})
            return as_json(403, {"error": exc.code, "message": str(exc)})
        # Only now does the service do the work.
        if verified.action == "notes.write":
            self.notes.append(json.loads(body).get("title", "untitled"))
        elif verified.action == "notes.purge":
            self.notes.clear()
        self.audit.append({"path": path, "result": "verified", "record": verified.record})
        return as_json(200, {
            "action": verified.action,
            "account": verified.subject,
            "human_verified": verified.human_verified,
            "single_use_grant": verified.grant.single_use,
            "notes": list(self.notes),
        })


# -- the broker --------------------------------------------------------------


class BrokerApp:
    """Where the person approves grants and the agent gets requests signed."""

    def __init__(self, public_url: str, service_url: str, link_secret: str):
        self.public_url = public_url
        self.service_url = service_url
        self.link_secret = link_secret
        self.rp_id = urlsplit(public_url).hostname
        self.broker = Broker(
            issuer=public_url, key=SigningKey.generate(), rp_id=self.rp_id, origin=public_url,
            risk_of=RISKS.get, cost_of=cost_of, outbox=Outbox(),
            services={service_url: ServiceEndpoints(service_url + "/grants",
                                                    service_url + "/events")},
        )
        self.passkey: tuple[str, bytes] | None = None
        self._registration_challenge: bytes | None = None
        self._notes_written = 0
        self._lock = threading.Lock()

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Response:
        path = target.split("?")[0]
        if method == "GET" and path == "/":
            return 200, "text/html; charset=utf-8", PAGE.read_bytes()
        if method == "GET" and path == "/.well-known/jwks.json":
            return as_json(200, self.broker.jwks())
        if method == "GET" and path == "/api/service":
            return as_json(200, http_get_json(self.service_url + "/audit"))
        routes = {
            "/api/register/options": self._register_options,
            "/api/register/verify": self._register_verify,
            "/api/grants/propose": self._propose,
            "/api/grants/activate": self._activate,
            "/api/grants/revoke": self._revoke,
            "/api/agent": self._agent,
        }
        if method != "POST" or path not in routes:
            return as_json(404, {"error": "not_found"})
        try:
            with self._lock:
                return as_json(200, routes[path](json.loads(body or b"{}")))
        except UndersignedError as exc:
            return as_json(400, {"error": exc.code, "message": str(exc)})
        except (KeyError, ValueError, TypeError) as exc:
            return as_json(400, {"error": "bad_request", "message": str(exc)})

    # -- passkey registration and account linking -----------------------------

    def _register_options(self, _data: dict) -> dict:
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name="undersigned demo broker",
            user_id=secrets.token_bytes(16),
            user_name="demo@undersigned.example",
            user_display_name="Demo user",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        self._registration_challenge = options.challenge
        return json.loads(options_to_json(options))

    def _register_verify(self, data: dict) -> dict:
        if self._registration_challenge is None:
            raise ValueError("no registration in progress")
        try:
            verification = verify_registration_response(
                credential=data["credential"],
                expected_challenge=self._registration_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.public_url,
                require_user_verification=True,
            )
        except Exception as exc:  # py_webauthn raises several unrelated types
            raise ValueError(f"registration did not verify: {exc}") from exc
        self._registration_challenge = None
        credential_id = bytes_to_base64url(verification.credential_id)
        public_key = verification.credential_public_key
        status, _ = http_post(
            self.service_url + "/link",
            json.dumps({"subject": ACCOUNT, "credential_id": credential_id,
                        "public_key": bytes_to_base64url(public_key)}).encode("utf-8"),
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.link_secret}"},
        )
        if status != 200:
            raise ValueError(f"service refused the account link (HTTP {status})")
        self.passkey = (credential_id, public_key)
        return {"credential_id": credential_id, "account": ACCOUNT}

    # -- grants ----------------------------------------------------------------

    def _propose(self, data: dict) -> dict:
        if self.passkey is None:
            raise ValueError("create a passkey first")
        if data["kind"] == "standing":
            grant = self.broker.propose(
                audience=self.service_url, subject=ACCOUNT,
                actions=["notes.read", "notes.write"], max_risk="medium",
                budget=Budget(3, "writes", "day"), duration=30 * 86_400,
            )
            summary = ["Read your notes", "Write up to 3 notes a day",
                       "Nothing above medium risk", "For 30 days, until you revoke it"]
        elif data["kind"] == "purge":
            grant = self.broker.propose(
                audience=self.service_url, subject=ACCOUNT, actions=["notes.purge"],
                max_risk="critical", single_use=True, duration=300,
                request=PinnedRequest.of("POST", f"{self.service_url}/v1/notes.purge",
                                         PURGE_BODY),
            )
            summary = ["Delete all your notes", "Once only, for this exact request",
                       "Expires in 5 minutes"]
        else:
            raise ValueError("unknown grant kind")
        return {
            "grant_id": grant.grant_id,
            "summary": summary,
            "document": grant.to_document(),
            "digest_hex": grant.digest_hex(),
            # The WebAuthn challenge IS the grant digest.
            "challenge": bytes_to_base64url(grant.digest()),
            "credential_id": self.passkey[0],
            "rp_id": self.rp_id,
        }

    def _activate(self, data: dict) -> dict:
        if self.passkey is None:
            raise ValueError("create a passkey first")
        evidence = HumanEvidence.from_assertion(data["credential"])
        if evidence.credential_id != self.passkey[0]:
            raise ValueError("assertion is from a different passkey")
        self.broker.activate(data["grant_id"], evidence, credential_public_key=self.passkey[1])
        delivered = not self.broker.outbox.pending()
        return {"grant_id": data["grant_id"], "delivered_to_service": delivered}

    def _revoke(self, data: dict) -> dict:
        self.broker.revoke(data["grant_id"])
        return {"revoked": data["grant_id"],
                "delivered_to_service": not self.broker.outbox.pending()}

    # -- the agent ---------------------------------------------------------------

    def _agent(self, data: dict) -> dict:
        """Act as the agent: ask the broker to sign a request, then send it."""
        scenario = data["scenario"]
        if scenario == "write":
            action = "notes.write"
            signed = json.dumps({"title": f"Note {self._notes_written + 1}"}).encode("utf-8")
            sent = signed
        elif scenario == "read":
            action, signed = "notes.read", b'{"query":"all"}'
            sent = signed
        elif scenario == "tamper":
            # The broker signs one body; a different one arrives at the service.
            action, signed, sent = "notes.read", b'{"query":"mine"}', b'{"query":"everyone"}'
        elif scenario == "purge":
            action, signed = "notes.purge", PURGE_BODY
            sent = signed
        else:
            raise ValueError("unknown scenario")

        url = f"{self.service_url}/v1/{action}"
        result: dict = {"scenario": scenario, "action": action, "url": url,
                        "body_signed": signed.decode(), "body_sent": sent.decode()}
        try:
            headers = self.broker.authorize(
                data["grant_id"], action=action, method="POST", url=url, body=signed)
        except StepUpRequired as exc:
            return {**result, "outcome": "step_up", "by": "broker", "code": exc.code}
        except Denied as exc:
            return {**result, "outcome": "refused", "by": "broker", "code": exc.code}

        request_headers = {**headers, "Content-Type": "application/json"}
        status, payload = http_post(url, sent, request_headers)
        if status == 409:  # the service lost or never got the grant: resend, retry once
            http_post(self.service_url + "/grants",
                      self.broker.receipt(data["grant_id"]).encode("ascii"),
                      {"Content-Type": "application/jwt"})
            status, payload = http_post(url, sent, request_headers)
        response = json.loads(payload or b"{}")
        if status == 200 and scenario == "write":
            self._notes_written += 1
        return {
            **result,
            "outcome": "verified" if status == 200 else "refused",
            "by": "service",
            "code": response.get("error", ""),
            "status": status,
            "headers": headers if status == 200 else {},
            "service_response": response,
        }


# -- plumbing ----------------------------------------------------------------


def _handler_for(app) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {name.lower(): value for name, value in self.headers.items()}
            try:
                status, content_type, payload = app.handle(
                    self.command, self.path, headers, body)
            except Exception as exc:  # keep the demo server alive
                status, content_type, payload = as_json(
                    500, {"error": "server_error", "message": str(exc)})
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _serve

        def log_message(self, *_args) -> None:
            pass

    return Handler


class _Late:
    """Lets a server be bound (to learn its port) before its app exists."""

    app = None

    def handle(self, *args) -> Response:
        return self.app.handle(*args)


def start(broker_port: int = 8000, service_port: int = 8001, host: str = "localhost"):
    """Start both servers on background threads. Port 0 picks a free port."""
    slots = [_Late(), _Late()]
    servers = [ThreadingHTTPServer((host, port), _handler_for(slot))
               for slot, port in zip(slots, (broker_port, service_port))]
    broker_url, service_url = (f"http://{host}:{server.server_address[1]}" for server in servers)
    link_secret = secrets.token_urlsafe(24)
    slots[0].app = BrokerApp(broker_url, service_url, link_secret)
    slots[1].app = NotesService(service_url, broker_url, link_secret)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers, broker_url, service_url


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--broker-port", type=int, default=8000)
    parser.add_argument("--service-port", type=int, default=8001)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    servers, broker_url, service_url = start(args.broker_port, args.service_port)
    print(f"broker   {broker_url}   (open this)")
    print(f"service  {service_url}")
    print("Ctrl-C to stop.")
    if not args.no_browser:
        webbrowser.open(broker_url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
