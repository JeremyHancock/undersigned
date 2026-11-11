# grantproof

A small Python library for one problem: when an AI agent acts on a person's
behalf, let the service receiving the request check for itself that the person
authorized it, and stop honoring that authorization the moment the person
revokes it.

It is for non-payment actions (write a record, send a message, delete data).
It has three parts:

- **Standing grants.** The person approves an envelope once: which actions,
  up to what risk, an optional budget, for how long. The agent then acts
  inside it without further prompts. Anything above the envelope "punches
  through" to a single-use approval for that one action.
- **Request-bound proof.** Every request made under a grant carries a signed
  proof tied to that exact method, URL and body.
- **Revocation push.** When the person revokes, the service is told, with
  retries.

This is a reference implementation, extracted from a larger project. State is
held in memory and nothing here has been security reviewed.

## Who signs what

Three parties: the **broker** (where the person approves things and the agent
gets its requests signed), the **service** (the API being called), and the
**person**, who holds a passkey registered with the broker.

| Object | Signed by | Says |
|---|---|---|
| Grant | the person's passkey | "I approve this envelope." The WebAuthn challenge is the SHA-256 of the canonical grant document. |
| Grant receipt | the broker | Carries the grant and the passkey assertion to the service, once. |
| Proof + HTTP signature | the broker | "This request is being made under that grant." Sent with every request. |
| Revocation event | the broker | "That grant has ended." |

The service runs the same envelope check as the broker, against the grant the
person signed, using its own risk rating for each action and its own spend
tally. A broker that claims more than the grant allows is refused.

## Try it

```bash
pip install -e ".[dev]"
python -m grantproof.demo     # the whole flow, in one process
pytest                        # 66 tests
```

## Use it

Broker side:

```python
from grantproof import Broker, Budget, SigningKey, StepUpRequired

broker = Broker(issuer="https://broker.example", key=SigningKey.generate(),
                rp_id="broker.example", origin="https://broker.example")

# 1. Draft a grant and show it to the person.
grant = broker.propose(audience="https://notes.example", subject="acct_42",
                       actions=["notes.read", "notes.write"], max_risk="medium",
                       budget=Budget(1000, "USD-cents", "month"), duration=30 * 86400)

# 2. Run a passkey ceremony with grant.digest() as the challenge, then:
receipt = broker.activate(grant.grant_id, evidence, credential_public_key=cose_key)
#    Deliver `receipt` to the service (or give Broker an Outbox and endpoints).

# 3. For each agent action:
try:
    headers = broker.authorize(grant.grant_id, action="notes.write", risk="medium",
                               method="POST", url=url, body=body)
except StepUpRequired as why:   # first_use, budget_exceeded, risk_exceeds_grant, ...
    ...                         # ask the person; for one action, a single-use grant
# Send the request with exactly that method, url and body, plus `headers`.

# 4. When the person revokes:
event = broker.revoke(grant.grant_id)
```

Service side:

```python
from grantproof import BrokerTrust, KeySet, Verifier

verifier = Verifier(
    audience="https://notes.example",
    brokers={"https://broker.example": BrokerTrust(
        KeySet.from_jwks(broker_jwks), rp_id="broker.example",
        origin="https://broker.example")},
    risk_of={"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}.get,
)

verifier.pin_passkey("acct_42", credential_id, cose_public_key)  # at account linking
verifier.accept_grant(receipt)                                   # POST /grants
verified = verifier.verify_request(method=..., url=..., headers=..., body=...)
verifier.accept_event(event)                                     # POST /events
```

`verified.record`, the request body and the grant receipt together are enough
to re-check the request later.

## On the wire

A request made under a grant:

```
POST /v1/notes HTTP/1.1
Content-Digest: sha-256=:z2xjziURawTjt3ailXYG4Y2Kx5jd4h4+wwiCrC374Ms=:
Grant-Proof: <JWT, typ grant-proof+jwt, 30 s lifetime>
Signature-Input: gp=("@method" "@target-uri" "content-digest" "grant-proof");created=...;expires=...;nonce="...";keyid="...";alg="ed25519";tag="grant-proof"
Signature: gp=:...:
```

The proof's claims: `iss`, `aud`, `sub` (the account at the service), `iat`,
`exp`, `jti`, `grant` (`id` and `digest`), and `authorization_details` naming
the one action and its amount.

## Standards used

| Part | Standard | Notes |
|---|---|---|
| Body binding | RFC 9530 `Content-Digest` | Checked against the RFC's example. |
| Request signature | RFC 9421 HTTP Message Signatures | A small profile: `ed25519` only. Checked against the RFC's Ed25519 example (B.2.6). |
| Grant and action description | RFC 9396 `authorization_details` | The `type` values and the limit fields (`max_risk`, `budget`) are this library's own; RFC 9396 registers none. |
| Grant digest | RFC 8785 JSON canonicalization | Integers only; floats are rejected. |
| Human evidence | WebAuthn assertion | Verified with `py_webauthn`. |
| Revocation event | RFC 8417 Security Event Token, shaped as an OpenID Shared Signals event | `sub_id`, no `sub`, no `exp`, `typ: secevent+jwt`. |
| Revocation delivery | RFC 8935 push | `push_error()` builds the error body. |
| Keys | JWK / JWKS, RFC 7638 thumbprint as `kid` | Ed25519. |

Two identifiers are minted here because nothing standard exists:
`urn:grantproof:event:grant-revoked` (neither CAEP nor RISC has a grant-revoked
event) and the `Grant-Proof` header.

## What it does and does not prove

- **Proved to the service:** the broker signed this exact request; the request
  fits a grant; and (when evidence is present) a pinned passkey signed that
  exact grant with user verification.
- **Not proved:** that the person saw an accurate description of the grant.
  The approval page belongs to the broker. WebAuthn does not define a way to
  bind displayed text to a signature outside payments, and its spec asks for
  random challenges; the grant's random id is what keeps the digest
  unpredictable here.
- **Trust at linking time:** the service learns the passkey's public key when
  the account is linked. If that step goes through the broker, the broker is
  trusted once, at that moment. After it, a stolen broker signing key cannot
  mint grants; it can still sign requests inside grants that already exist.
- **Per-request, the person is not present.** Under a standing grant the
  person signs the envelope, not each request. Single-use grants can be pinned
  to one request body.
- **Counting:** an action is counted against the budget when the broker signs
  it, whether or not the request then succeeds.

## Not included

Persistence (both sides keep state in memory), an HTTP server, the approval
page and passkey registration, key rotation, an audit log, and algorithms
other than Ed25519.
