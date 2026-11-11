"""A walk through the whole flow in one process: ``python -m undersigned.demo``.

A broker, a notes service and a human with a (software) passkey. No network:
deliveries are handed straight to the service.
"""

from __future__ import annotations

from undersigned import (
    Broker, BrokerTrust, Budget, UndersignedError, KeySet, Outbox, ServiceEndpoints, SigningKey,
    StepUpRequired, Verifier,
)
from undersigned.httpsig import content_digest
from undersigned.testing import SoftAuthenticator

BROKER = "https://broker.example"
SERVICE = "https://notes.example"
ACCOUNT = "acct_42"
RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}


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
        outbox=Outbox(deliver),
        services={SERVICE: ServiceEndpoints(f"{SERVICE}/grants", f"{SERVICE}/events")},
    )
    verifier = Verifier(
        audience=SERVICE,
        brokers={BROKER: BrokerTrust(KeySet.from_jwks(broker.jwks()), "broker.example", BROKER)},
        risk_of=RISKS.get,
    )
    verifier.pin_passkey(ACCOUNT, passkey.credential_id, passkey.cose_public_key)
    print("1. Account linked: the service pinned the human's passkey.")

    def approve(**envelope):
        grant = broker.propose(audience=SERVICE, subject=ACCOUNT, **envelope)
        evidence = passkey.sign(grant.digest(), rp_id="broker.example", origin=BROKER)
        broker.activate(grant.grant_id, evidence, credential_public_key=passkey.cose_public_key)
        return grant

    def act(grant, action, body, amount=0):
        url = f"{SERVICE}/v1/{action}"
        headers = broker.authorize(grant.grant_id, action=action, risk=RISKS[action],
                                   method="POST", url=url, body=body, amount=amount)
        return verifier.verify_request(method="POST", url=url, headers=headers, body=body), headers

    standing = approve(actions=["notes.read", "notes.write"], duration=30 * 86_400,
                       max_risk="medium", budget=Budget(1000, "USD-cents", "month"))
    print(f"2. Human signed a standing grant {standing.grant_id[:8]}: read and write, "
          "medium risk, 1000 cents a month, 30 days.")

    verified, headers = act(standing, "notes.write", b'{"title":"hello"}', amount=250)
    print(f"3. Agent wrote a note. Service verified: action={verified.action}, "
          f"human_verified={verified.human_verified}.")
    print("   Headers the broker attached:")
    for name, value in headers.items():
        print(f"     {name}: {value[:68]}{'...' if len(value) > 68 else ''}")

    try:
        verifier.verify_request(method="POST", url=f"{SERVICE}/v1/notes.write",
                                headers=headers, body=b'{"title":"tampered"}')
    except UndersignedError as exc:
        print(f"4. Same headers, different body: refused ({exc.code}).")

    try:
        act(standing, "notes.write", b'{"title":"pricey"}', amount=900)
    except StepUpRequired as exc:
        print(f"5. Over budget: broker asks the human ({exc.code}).")

    purge = b'{"confirm":"all"}'
    try:
        act(standing, "notes.purge", purge)
    except StepUpRequired as exc:
        print(f"6. Critical action under the standing grant: punches through ({exc.code}).")
    once = approve(actions=["notes.purge"], duration=300, max_risk="critical", single_use=True,
                   content_digest=content_digest(purge))
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
