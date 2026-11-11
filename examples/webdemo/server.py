"""A browser demo with a real passkey and real HTTP between two servers.

    python examples/webdemo/server.py

starts a broker (http://localhost:8000, with the page you click through) and a
notes service (http://localhost:8001). The two only talk over HTTP. You create
a passkey, sign a standing grant with it, and watch an agent act inside and
outside the envelope.

Every visitor gets their own session: an account, a passkey and notes of their
own, forgotten after 30 idle minutes. State is in memory. ``--hosted`` runs it
for the public internet behind a TLS-terminating proxy (see ``fly.toml``).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, quote, urlsplit

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

RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}
PURGE_BODY = b'{"confirm":"delete all notes"}'
PAGE = Path(__file__).with_name("index.html")
COOKIE = "undersigned_session"
MAX_BODY = 64 * 1024

Response = tuple[int, str, bytes, dict[str, str]]


def cost_of(action: str, _body: bytes) -> int:
    """What an action draws from a budget. Broker and service each apply it."""
    return 1 if action == "notes.write" else 0


@dataclass(frozen=True)
class Limits:
    session_idle_seconds: int = 30 * 60
    max_sessions: int = 300
    max_sessions_per_client: int = 5
    requests_per_minute: int = 90


def as_json(status: int, payload, headers: dict[str, str] | None = None) -> Response:
    return status, "application/json", json.dumps(payload).encode("utf-8"), headers or {}


def http_post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def http_get_json(url: str, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


# -- the notes service -------------------------------------------------------


class NotesService:
    """The API being called. It knows the broker only by its name and its keys."""

    def __init__(self, public_url: str, broker_issuer: str, broker_jwks_url: str,
                 link_secret: str):
        self.public_url = public_url
        self.broker_issuer = broker_issuer
        self.broker_jwks_url = broker_jwks_url
        self.link_secret = link_secret
        self.notes: dict[str, list[str]] = {}
        self.accepted: dict[str, list[dict]] = {}  # per account: evidence for each request
        self.refused: deque[str] = deque(maxlen=200)  # recent refusal codes
        self._verifier: Verifier | None = None
        self._lock = threading.Lock()

    @property
    def verifier(self) -> Verifier:
        if self._verifier is None:
            # Fetch the broker's public keys the way any service would.
            keys = KeySet.from_jwks(http_get_json(self.broker_jwks_url))
            trust = BrokerTrust(keys, rp_id=urlsplit(self.broker_issuer).hostname,
                                origin=self.broker_issuer)
            self._verifier = Verifier(
                audience=self.public_url, brokers={self.broker_issuer: trust},
                risk_of=RISKS.get, cost_of=cost_of)
        return self._verifier

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes,
               _client: str) -> Response:
        path = target.split("?")[0]
        with self._lock:
            if path in ("/link", "/unlink", "/audit"):
                # Account management is between the broker and the service only.
                if not secrets.compare_digest(headers.get("authorization", ""),
                                              f"Bearer {self.link_secret}"):
                    return as_json(401, {"error": "unauthorized"})
                if method == "GET" and path == "/audit":
                    subject = parse_qs(urlsplit(target).query).get("subject", [""])[0]
                    return as_json(200, {"notes": self.notes.get(subject, []),
                                         "accepted": self.accepted.get(subject, []),
                                         "refused": list(self.refused)})
                if method == "POST":
                    return self._link(path, json.loads(body))
            if method != "POST":
                return as_json(404, {"error": "not_found"})
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
                return 202, "application/json", b"", {}
            if path.startswith("/v1/"):
                return self._action(path.removeprefix("/v1/"), target, headers, body)
            return as_json(404, {"error": "not_found"})

    def _link(self, path: str, data: dict) -> Response:
        """Account linking: the one moment the service trusts the broker's word."""
        subject = data["subject"]
        if path == "/unlink":
            self.verifier.forget_account(self.broker_issuer, subject)
            self.notes.pop(subject, None)
            self.accepted.pop(subject, None)
            return as_json(200, {"unlinked": subject})
        self.verifier.pin_passkey(self.broker_issuer, subject, data["credential_id"],
                                  base64url_to_bytes(data["public_key"]))
        return as_json(200, {"linked": subject})

    def _action(self, action: str, target: str, headers: dict[str, str],
                body: bytes) -> Response:
        try:
            # The action comes from this service's routing, and the URL is the
            # full request target, query string included.
            verified = self.verifier.verify_request(
                action=action, method="POST", url=self.public_url + target, headers=headers,
                body=body)
        except UnknownGrant as exc:
            return as_json(409, {"error": exc.code, "message": str(exc)})
        except UndersignedError as exc:
            self.refused.append(exc.code)
            return as_json(403, {"error": exc.code, "message": str(exc)})
        # Only now does the service do the work, for the account the grant names.
        notes = self.notes.setdefault(verified.subject, [])
        if action == "notes.write":
            notes.append(str(json.loads(body).get("title", "untitled"))[:80])
        elif action == "notes.purge":
            notes.clear()
        self.accepted.setdefault(verified.subject, []).append(verified.record)
        return as_json(200, {
            "action": verified.action,
            "account": verified.subject,
            "human_verified": verified.human_verified,
            "single_use_grant": verified.grant.single_use,
            "notes": list(notes),
        })


# -- the broker --------------------------------------------------------------


@dataclass
class Session:
    id: str
    subject: str
    client: str
    last_seen: float
    passkey: tuple[str, bytes] | None = None
    registration_challenge: bytes | None = None
    grants: set[str] = field(default_factory=set)
    notes_written: int = 0


class TooBusy(Exception):
    """No room for another session right now."""


class BrokerApp:
    """Where the person approves grants and the agent gets requests signed."""

    def __init__(self, public_url: str, service_url: str, link_secret: str, *,
                 limits: Limits = Limits(), clock: Callable[[], float] = time.time):
        self.public_url = public_url
        self.service_url = service_url
        self.link_secret = link_secret
        self.limits = limits
        self._clock = clock
        self.rp_id = urlsplit(public_url).hostname
        self.broker = Broker(
            issuer=public_url, key=SigningKey.generate(), rp_id=self.rp_id, origin=public_url,
            risk_of=RISKS.get, cost_of=cost_of, outbox=Outbox(),
            services={service_url: ServiceEndpoints(service_url + "/grants",
                                                    service_url + "/events")},
        )
        self.sessions: dict[str, Session] = {}
        self._requests: dict[str, deque[float]] = {}
        self._last_sweep = 0.0
        self._lock = threading.Lock()

    @property
    def _service_auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.link_secret}"}

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes,
               client: str) -> Response:
        path = target.split("?")[0]
        if method == "GET" and path == "/":
            return 200, "text/html; charset=utf-8", PAGE.read_bytes(), {
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'"),
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        if method == "GET" and path == "/.well-known/jwks.json":
            return as_json(200, self.broker.jwks())
        if method == "GET" and path == "/healthz":
            return as_json(200, {"ok": True})
        if not path.startswith("/api/"):
            return as_json(404, {"error": "not_found"})

        routes = {
            "/api/register/options": self._register_options,
            "/api/register/verify": self._register_verify,
            "/api/grants/propose": self._propose,
            "/api/grants/activate": self._activate,
            "/api/grants/revoke": self._revoke,
            "/api/agent": self._agent,
        }
        with self._lock:
            now = self._clock()
            self._sweep(now)
            if not self._within_rate(client, now):
                return as_json(429, {"error": "rate_limited",
                                     "message": "Too many requests. Wait a minute."})
            try:
                session, cookie = self._session(headers, client, now)
            except TooBusy as exc:
                return as_json(503, {"error": "busy", "message": str(exc)})
            try:
                if method == "GET" and path == "/api/service":
                    state = http_get_json(
                        f"{self.service_url}/audit?subject={quote(session.subject)}",
                        self._service_auth)
                    return as_json(200, {"notes": state["notes"]}, cookie)
                if method != "POST" or path not in routes:
                    return as_json(404, {"error": "not_found"}, cookie)
                return as_json(200, routes[path](session, json.loads(body or b"{}")), cookie)
            except UndersignedError as exc:
                return as_json(400, {"error": exc.code, "message": str(exc)}, cookie)
            except (KeyError, ValueError, TypeError) as exc:
                return as_json(400, {"error": "bad_request", "message": str(exc)}, cookie)

    # -- sessions and limits ---------------------------------------------------

    def _within_rate(self, client: str, now: float) -> bool:
        recent = self._requests.setdefault(client, deque())
        while recent and recent[0] <= now - 60:
            recent.popleft()
        if len(recent) >= self.limits.requests_per_minute:
            return False
        recent.append(now)
        return True

    def _session(self, headers: dict[str, str], client: str,
                 now: float) -> tuple[Session, dict[str, str]]:
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and value in self.sessions:
                session = self.sessions[value]
                session.last_seen = now
                return session, {}
        if len(self.sessions) >= self.limits.max_sessions:
            raise TooBusy("The demo is full right now. Try again in a few minutes.")
        mine = sum(1 for s in self.sessions.values() if s.client == client)
        if mine >= self.limits.max_sessions_per_client:
            raise TooBusy("Too many sessions from this address. Try again later.")
        session = Session(id=secrets.token_urlsafe(32), subject=f"acct_{secrets.token_hex(6)}",
                          client=client, last_seen=now)
        self.sessions[session.id] = session
        attributes = f"Path=/; HttpOnly; SameSite=Strict; Max-Age={self.limits.session_idle_seconds}"
        if self.public_url.startswith("https://"):
            attributes += "; Secure"
        return session, {"Set-Cookie": f"{COOKIE}={session.id}; {attributes}"}

    def _sweep(self, now: float) -> None:
        """Forget idle sessions, here and at the service."""
        if now - self._last_sweep < 30:
            return
        self._last_sweep = now
        cutoff = now - self.limits.session_idle_seconds
        for session in [s for s in self.sessions.values() if s.last_seen < cutoff]:
            del self.sessions[session.id]
            for grant_id in session.grants:
                self.broker.forget(grant_id)
            http_post(self.service_url + "/unlink",
                      json.dumps({"subject": session.subject}).encode("utf-8"),
                      {"Content-Type": "application/json", **self._service_auth})
        self.broker.outbox.forget_delivered()
        self._requests = {c: r for c, r in self._requests.items() if r and r[-1] > now - 60}

    def _own(self, session: Session, grant_id: str) -> str:
        if grant_id not in session.grants:
            raise ValueError("no such grant in this session")
        return grant_id

    # -- passkey registration and account linking -----------------------------

    def _register_options(self, session: Session, _data: dict) -> dict:
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name="undersigned demo broker",
            user_id=secrets.token_bytes(16),
            user_name=f"{session.subject}@undersigned.example",
            user_display_name="undersigned demo",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        session.registration_challenge = options.challenge
        return json.loads(options_to_json(options))

    def _register_verify(self, session: Session, data: dict) -> dict:
        if session.registration_challenge is None:
            raise ValueError("no registration in progress")
        if session.passkey is not None:
            raise ValueError("this session already has a passkey")
        try:
            verification = verify_registration_response(
                credential=data["credential"],
                expected_challenge=session.registration_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.public_url,
                require_user_verification=True,
            )
        except Exception as exc:  # py_webauthn raises several unrelated types
            raise ValueError(f"registration did not verify: {exc}") from exc
        session.registration_challenge = None
        credential_id = bytes_to_base64url(verification.credential_id)
        public_key = verification.credential_public_key
        status, _ = http_post(
            self.service_url + "/link",
            json.dumps({"subject": session.subject, "credential_id": credential_id,
                        "public_key": bytes_to_base64url(public_key)}).encode("utf-8"),
            {"Content-Type": "application/json", **self._service_auth},
        )
        if status != 200:
            raise ValueError(f"service refused the account link (HTTP {status})")
        session.passkey = (credential_id, public_key)
        return {"credential_id": credential_id, "account": session.subject}

    # -- grants ----------------------------------------------------------------

    def _propose(self, session: Session, data: dict) -> dict:
        if session.passkey is None:
            raise ValueError("create a passkey first")
        if len(session.grants) >= 20:
            raise ValueError("this session has made enough grants; reload to start again")
        if data["kind"] == "standing":
            grant = self.broker.propose(
                audience=self.service_url, subject=session.subject,
                actions=["notes.read", "notes.write"], max_risk="medium",
                budget=Budget(3, "writes", "day"), duration=30 * 86_400,
            )
            summary = ["Read your notes", "Write up to 3 notes a day",
                       "Nothing above medium risk", "For 30 days, until you revoke it"]
        elif data["kind"] == "purge":
            grant = self.broker.propose(
                audience=self.service_url, subject=session.subject, actions=["notes.purge"],
                max_risk="critical", single_use=True, duration=300,
                request=PinnedRequest.of("POST", f"{self.service_url}/v1/notes.purge",
                                         PURGE_BODY),
            )
            summary = ["Delete all your notes", "Once only, for this exact request",
                       "Expires in 5 minutes"]
        else:
            raise ValueError("unknown grant kind")
        session.grants.add(grant.grant_id)
        return {
            "grant_id": grant.grant_id,
            "summary": summary,
            "document": grant.to_document(),
            "digest_hex": grant.digest_hex(),
            # The WebAuthn challenge IS the grant digest.
            "challenge": bytes_to_base64url(grant.digest()),
            "credential_id": session.passkey[0],
            "rp_id": self.rp_id,
        }

    def _activate(self, session: Session, data: dict) -> dict:
        if session.passkey is None:
            raise ValueError("create a passkey first")
        grant_id = self._own(session, data["grant_id"])
        evidence = HumanEvidence.from_assertion(data["credential"])
        if evidence.credential_id != session.passkey[0]:
            raise ValueError("assertion is from a different passkey")
        self.broker.activate(grant_id, evidence, credential_public_key=session.passkey[1])
        return {"grant_id": grant_id, "delivered_to_service": not self.broker.outbox.pending()}

    def _revoke(self, session: Session, data: dict) -> dict:
        grant_id = self._own(session, data["grant_id"])
        self.broker.revoke(grant_id)
        return {"revoked": grant_id, "delivered_to_service": not self.broker.outbox.pending()}

    # -- the agent ---------------------------------------------------------------

    def _agent(self, session: Session, data: dict) -> dict:
        """Act as the agent: ask the broker to sign a request, then send it."""
        grant_id = self._own(session, data["grant_id"])
        scenario = data["scenario"]
        if scenario == "write":
            action = "notes.write"
            signed = json.dumps({"title": f"Note {session.notes_written + 1}"}).encode("utf-8")
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
            headers = self.broker.authorize(grant_id, action=action, method="POST", url=url,
                                            body=signed)
        except StepUpRequired as exc:
            return {**result, "outcome": "step_up", "by": "broker", "code": exc.code}
        except Denied as exc:
            return {**result, "outcome": "refused", "by": "broker", "code": exc.code}

        request_headers = {**headers, "Content-Type": "application/json"}
        status, payload = http_post(url, sent, request_headers)
        if status == 409:  # the service lost or never got the grant: resend, retry once
            http_post(self.service_url + "/grants",
                      self.broker.receipt(grant_id).encode("ascii"),
                      {"Content-Type": "application/jwt"})
            status, payload = http_post(url, sent, request_headers)
        response = json.loads(payload or b"{}")
        if status == 200 and scenario == "write":
            session.notes_written += 1
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


def _handler_for(app, trust_proxy: bool) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        timeout = 15  # seconds a client may stall before the connection is dropped
        server_version = "undersigned-demo"
        sys_version = ""

        def _serve(self) -> None:
            headers = {name.lower(): value for name, value in self.headers.items()}
            client = self.client_address[0]
            if trust_proxy:
                client = headers.get("fly-client-ip", client)
            try:
                length = int(headers.get("content-length") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                status, content_type, payload, extra = as_json(413, {"error": "too_large"})
                self.close_connection = True
            else:
                body = self.rfile.read(length) if length else b""
                try:
                    status, content_type, payload, extra = app.handle(
                        self.command, self.path, headers, body, client)
                except Exception:  # keep the demo server alive, say nothing specific
                    status, content_type, payload, extra = as_json(500, {"error": "server_error"})
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in extra.items():
                self.send_header(name, value)
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


def start(broker_port: int = 8000, service_port: int = 8001, *, public_url: str | None = None,
          bind: str = "localhost", trust_proxy: bool = False, limits: Limits = Limits(),
          clock: Callable[[], float] = time.time):
    """Start both servers on background threads. Port 0 picks a free port.

    The notes service always listens on localhost only. ``public_url`` is the
    address people reach the broker at, when that differs from where it binds.
    """
    slots = [_Late(), _Late()]
    broker_server = ThreadingHTTPServer((bind, broker_port), _handler_for(slots[0], trust_proxy))
    service_server = ThreadingHTTPServer(("localhost", service_port),
                                         _handler_for(slots[1], False))
    local_broker_url = f"http://localhost:{broker_server.server_address[1]}"
    broker_url = (public_url or local_broker_url).rstrip("/")
    service_url = f"http://localhost:{service_server.server_address[1]}"
    link_secret = secrets.token_urlsafe(24)
    slots[0].app = BrokerApp(broker_url, service_url, link_secret, limits=limits, clock=clock)
    slots[1].app = NotesService(service_url, broker_url,
                                local_broker_url + "/.well-known/jwks.json", link_secret)
    broker_server.app, service_server.app = slots[0].app, slots[1].app
    servers = [broker_server, service_server]
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers, broker_url, service_url


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--broker-port", type=int, default=8000)
    parser.add_argument("--service-port", type=int, default=8001)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--hosted", action="store_true",
                        help="serve the public internet: needs PUBLIC_URL, honors PORT")
    args = parser.parse_args()
    if args.hosted:
        public_url = os.environ["PUBLIC_URL"]
        servers, broker_url, service_url = start(
            int(os.environ.get("PORT", "8080")), args.service_port, public_url=public_url,
            bind="0.0.0.0", trust_proxy=True)
    else:
        servers, broker_url, service_url = start(args.broker_port, args.service_port)
    print(f"broker   {broker_url}   (open this)", flush=True)
    print(f"service  {service_url}", flush=True)
    if not args.hosted and not args.no_browser:
        webbrowser.open(broker_url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
