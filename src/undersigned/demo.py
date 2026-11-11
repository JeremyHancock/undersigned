"""A walk through the whole flow in one process: ``python -m undersigned.demo``.

A broker, a notes service and a human with a (software) passkey. No network:
deliveries are handed straight to the service. For real HTTP and a real
passkey, see ``examples/webdemo``.
"""

from __future__ import annotations

from undersigned import (
    Broker, BrokerTrust, Budget, KeySet, Outbox, PinnedRequest, ServiceEndpoints, SigningKey,
    StepUpRequired, UndersignedError, Verifier,
)
from undersigned.testing import SoftAuthenticator

BROKER = "https://broker.example"
SERVICE = "https://notes.example"
ACCOUNT = "acct_42"
RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}


def cost_of(action: str, _body: bytes) -> int:
    """Each write draws one unit from the budget. Both sides apply this."""
    return 1 if action == "notes.write" else 0


def main() -> None:
    passkey = SoftAuthenticator()
    verifier: Verifier

    def deliver(url: str, body: bytes, _headers: dict) -> int:
        if url.endswith("/grants"):
            verifier.accept_grant(body.decode())
        else:
            verifier.accept_event(body.decode())
        return 202

    broker = Broker(
        issuer=BROKER, key=SigningKey.generate(), rp_id="broker.example", origin=BROKER,
        risk_of=RISKS.get, cost_of=cost_of, outbox=Outbox(deliver),
        services={SERVICE: ServiceEndpoints(f"{SERVICE}/grants", f"{SERVICE}/events")},
    )
    verifier = Verifier(
        audience=SERVICE,
        brokers={BROKER: BrokerTrust(KeySet.from_jwks(broker.jwks()), "broker.example", BROKER)},
        risk_of=RISKS.get, cost_of=cost_of,
    )
    verifier.pin_passkey(BROKER, ACCOUNT, passkey.credential_id, passkey.cose_public_key)
    print("1. Account linked: the service pinned the human's passkey.")

    def approve(**envelope):
        grant = broker.propose(audience=SERVICE, subject=ACCOUNT, **envelope)
        evidence = passkey.sign(grant.digest(), rp_id="broker.example", origin=BROKER)
        broker.activate(grant.grant_id, evidence, credential_public_key=passkey.cose_public_key)
        return grant

    def act(grant, action, body):
        url = f"{SERVICE}/v1/{action}"
        headers = broker.authorize(grant.grant_id, action=action, method="POST", url=url,
                                   body=body)
        verified = verifier.verify_request(action=action, method="POST", url=url,
                                           headers=headers, body=body)
        return verified, headers

    standing = approve(actions=["notes.read", "notes.write"], duration=30 * 86_400,
                       max_risk="medium", budget=Budget(3, "writes", "day"))
    print(f"2. Human signed a standing grant {standing.grant_id[:8]}: read and write, "
          "medium risk, 3 writes a day, 30 days.")

    verified, headers = act(standing, "notes.write", b'{"title":"hello"}')
    print(f"3. Agent wrote a note. Service verified: action={verified.action}, "
          f"human_verified={verified.human_verified}.")
    print("   Headers the broker attached:")
    for name, value in headers.items():
        print(f"     {name}: {value[:68]}{'...' if len(value) > 68 else ''}")

    try:
        verifier.verify_request(action="notes.write", method="POST",
                                url=f"{SERVICE}/v1/notes.write", headers=headers,
                                body=b'{"title":"tampered"}')
    except UndersignedError as exc:
        print(f"4. Same headers, different body: refused ({exc.code}).")

    act(standing, "notes.write", b'{"title":"two"}')
    act(standing, "notes.write", b'{"title":"three"}')
    try:
        act(standing, "notes.write", b'{"title":"four"}')
    except StepUpRequired as exc:
        print(f"5. Fourth write today: broker asks the human ({exc.code}).")

    purge = b'{"confirm":"all"}'
    try:
        act(standing, "notes.purge", purge)
    except StepUpRequired as exc:
        print(f"6. Critical action under the standing grant: punches through ({exc.code}).")
    once = approve(actions=["notes.purge"], duration=300, max_risk="critical", single_use=True,
                   request=PinnedRequest.of("POST", f"{SERVICE}/v1/notes.purge", purge))
    act(once, "notes.purge", purge)
    print("   Human signed a single-use grant pinned to that exact request; it went through.")
    try:
        act(once, "notes.purge", purge)
    except UndersignedError as exc:
        print(f"   Second use of it: refused ({exc.code}).")

    broker.revoke(standing.grant_id)
    try:
        act(standing, "notes.read", b"{}")
    except UndersignedError as exc:
        print(f"7. Human revoked the standing grant: broker refuses ({exc.code}), "
              "and the service was told.")


if __name__ == "__main__":
    main()
