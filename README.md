# undersigned

[![tests](https://github.com/JeremyHancock/undersigned/actions/workflows/test.yml/badge.svg)](https://github.com/JeremyHancock/undersigned/actions/workflows/test.yml)

When an AI agent calls an API on someone's behalf, the API usually sees a
bearer token and has to take the rest on trust. `undersigned` is a small
Python library that lets the service check three things for itself:

- a specific person approved a bounded set of actions, and signed that
  approval with their own passkey;
- this exact request (method, URL and body) is being made under that
  approval;
- the approval has not been revoked.

It is aimed at non-payment actions: writing a record, sending a message,
deleting data.

This is a reference implementation. State is held in memory. The automated
tests use a software authenticator; the browser demo below has been run by
hand with a real passkey. It has had one adversarial review pass by
an AI reviewer, whose findings are fixed and covered by tests; that is not a
security audit.

## The idea

Asking a person to approve every agent action does not scale; letting the
agent do anything does not either. Here the person approves an **envelope**
once, and only what falls outside it comes back to them.

- **Standing grant.** Which actions, up to what risk, an optional budget, for
  how long. Inside it the agent acts without further prompts.
- **Punch-through.** High and critical actions can never sit in a standing
  grant. Each needs a single-use grant, which can be pinned to one exact
  request: method, URL and body.
- **Proof on every request.** A short-lived token and an HTTP signature bind
  the request to the grant.
- **Revocation push.** When the person revokes, the service is told, with
  retries.

## See it run

```bash
pip install -e ".[dev]"
python -m undersigned.demo
pytest
```

The demo plays a broker, a notes service and a person with a passkey in one
process:

```
1. Account linked: the service pinned the human's passkey.
2. Human signed a standing grant 386fbccc: read and write, medium risk, 3 writes a day, 30 days.
3. Agent wrote a note. Service verified: action=notes.write, human_verified=True.
4. Same headers, different body: refused (digest_mismatch).
5. Fourth write today: broker asks the human (budget_exceeded).
6. Critical action under the standing grant: punches through (action_not_covered).
   Human signed a single-use grant pinned to that exact request; it went through.
   Second use of it: refused (grant_already_used).
7. Human revoked the standing grant: broker refuses (grant_revoked), and the service was told.
```

### With a real passkey, over HTTP

```bash
python examples/webdemo/server.py
```

This starts two servers that only talk over HTTP: a broker at
`http://localhost:8000` (it opens in your browser) and a notes service at
`http://localhost:8001`. You create a passkey, sign a standing grant with it,
then let the agent write notes, exceed its budget, send a tampered request,
and try to delete everything. It is a single-user local demo: one account,
state in memory. `tests/test_webdemo.py` drives the same two servers with a
software passkey.

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
person signed. It decides for itself which action an endpoint performs, how
risky that action is and what it costs, and keeps its own spend tally. Nothing
the broker says about risk or cost is taken on trust, so a broker (or a stolen
broker key) that claims more than the grant allows is refused.

## Use it

Broker side:

```python
from undersigned import Broker, Budget, SigningKey, StepUpRequired

RISKS = {"notes.read": "low", "notes.write": "medium", "notes.purge": "critical"}
def cost_of(action, body):          # what an action draws from a budget
    return 1 if action == "notes.write" else 0

broker = Broker(issuer="https://broker.example", key=SigningKey.generate(),
                rp_id="broker.example", origin="https://broker.example",
                risk_of=RISKS.get, cost_of=cost_of)

# 1. Draft a grant and show it to the person.
grant = broker.propose(audience="https://notes.example", subject="acct_42",
                       actions=["notes.read", "notes.write"], max_risk="medium",
                       budget=Budget(3, "writes", "day"), duration=30 * 86400)

# 2. Run a passkey ceremony with grant.digest() as the challenge, then:
receipt = broker.activate(grant.grant_id, evidence, credential_public_key=cose_key)
#    Deliver `receipt` to the service (or give Broker an Outbox and endpoints).

# 3. For each agent action. Risk and cost come from the broker's own catalog,
#    never from the agent asking.
try:
    headers = broker.authorize(grant.grant_id, action="notes.write",
                               method="POST", url=url, body=body)
except StepUpRequired as why:   # first_use, budget_exceeded, risk_exceeds_grant, ...
    ...                         # ask the person; for one action, a single-use grant
# Send the request with exactly that method, url and body, plus `headers`.

# 4. When the person revokes:
event = broker.revoke(grant.grant_id)
```

Service side:

```python
from undersigned import BrokerTrust, KeySet, Verifier

verifier = Verifier(
    audience="https://notes.example",
    brokers={"https://broker.example": BrokerTrust(
        KeySet.from_jwks(broker_jwks), rp_id="broker.example",
        origin="https://broker.example")},
    risk_of=RISKS.get, cost_of=cost_of,      # the service's own catalog
)

# At account linking:
verifier.pin_passkey("https://broker.example", "acct_42", credential_id, cose_public_key)
verifier.accept_grant(receipt)                                   # POST /grants
verifier.accept_event(event)                                     # POST /events

# In the handler for POST /v1/notes. `action` is what this endpoint does, from
# your routing; `url` is the full URL the request was sent to, query included.
verified = verifier.verify_request(action="notes.write", method="POST", url=url,
                                   headers=headers, body=body)
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
`urn:undersigned:event:grant-revoked` (neither CAEP nor RISC has a
grant-revoked event) and the `Grant-Proof` header.

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
  to one request (method, URL and body).
- **The catalog is yours.** Risk and cost are whatever `risk_of` and `cost_of`
  say on each side. The defaults treat every action as free, so a budget only
  bites once you supply `cost_of`.
- **Counting:** an action is counted against the budget when the broker signs
  it, whether or not the request then succeeds.

## Not included

Persistence (both sides keep state in memory), an HTTP server, the approval
page and passkey registration, key rotation, an audit log, and algorithms
other than Ed25519.

## Layout

| Module | What it holds |
|---|---|
| `grant.py`, `policy.py` | The grant document and the envelope check both sides run. |
| `evidence.py` | Verifying the passkey assertion over a grant. |
| `httpsig.py`, `tokens.py` | The wire formats. |
| `broker.py`, `service.py` | The two roles. |
| `outbox.py` | Delivery with retries. |
| `testing.py`, `demo.py` | A software passkey and the walkthrough. |

## License

MIT.
