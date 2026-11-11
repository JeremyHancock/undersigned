"""The three signed tokens a broker sends a service.

* **grant receipt**: the grant document plus the human's evidence, sent once.
* **proof**: a short-lived token attached to each request made under a grant.
* **revocation event**: a Security Event Token (RFC 8417, shaped as an OpenID
  Shared Signals event) saying a grant ended.

All are JWTs signed with the broker's Ed25519 key (``alg: EdDSA``).
"""

from __future__ import annotations

import uuid

import jwt

from grantproof.errors import SignatureError
from grantproof.keys import KeySet, SigningKey

PROOF_TYP = "grant-proof+jwt"
RECEIPT_TYP = "grant-receipt+jwt"
SET_TYP = "secevent+jwt"

ACTION_DETAIL_TYPE = "urn:grantproof:action:v1"
EVENT_GRANT_REVOKED = "urn:grantproof:event:grant-revoked"

PROOF_HEADER = "Grant-Proof"
RECEIPT_MEDIA_TYPE = "application/jwt"
SET_MEDIA_TYPE = "application/secevent+jwt"


def _encode(key: SigningKey, typ: str, claims: dict) -> str:
    return jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"typ": typ, "kid": key.kid})


def peek_issuer(token: str) -> str:
    """Read ``iss`` without verifying, to choose which broker's keys to use."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise SignatureError(f"malformed token: {exc}", code="token_malformed") from exc
    issuer = claims.get("iss")
    if not isinstance(issuer, str):
        raise SignatureError("token has no issuer", code="token_malformed")
    return issuer


def decode(
    token: str,
    keys: KeySet,
    *,
    typ: str,
    issuer: str,
    audience: str,
    now: int,
    leeway: int = 5,
    expires: bool = True,
    max_lifetime: int = 300,
) -> dict:
    """Verify signature, type, issuer, audience and (optionally) lifetime."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise SignatureError(f"malformed token: {exc}", code="token_malformed") from exc
    if header.get("alg") != "EdDSA":
        raise SignatureError("unsupported token algorithm", code="unsupported_algorithm")
    if header.get("typ") != typ:
        raise SignatureError(f"expected a {typ} token", code="token_wrong_type")
    required = ["iss", "aud", "iat", "jti"] + (["exp"] if expires else [])
    try:
        claims = jwt.decode(
            token,
            keys.get(header.get("kid")),
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=audience,
            # Time checks are done below against the caller's clock.
            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False,
                     "require": required},
        )
    except jwt.PyJWTError as exc:
        raise SignatureError(f"token did not verify: {exc}", code="token_invalid") from exc
    issued = claims["iat"]
    if not isinstance(issued, int) or issued > now + leeway:
        raise SignatureError("token issued in the future", code="token_not_yet_valid")
    if expires:
        expiry = claims["exp"]
        if not isinstance(expiry, int) or now > expiry + leeway:
            raise SignatureError("token expired", code="token_expired")
        if expiry - issued > max_lifetime:
            raise SignatureError("token lifetime too long", code="token_lifetime")
    return claims


# -- grant receipt -----------------------------------------------------------


def encode_receipt(key: SigningKey, *, document: dict, evidence: dict | None, now: int) -> str:
    return _encode(key, RECEIPT_TYP, {
        "iss": document["iss"],
        "aud": document["aud"],
        "iat": now,
        "jti": str(uuid.uuid4()),
        "grant": document,
        "evidence": evidence,
    })


# -- per-request proof -------------------------------------------------------


def encode_proof(
    key: SigningKey,
    *,
    issuer: str,
    audience: str,
    subject: str,
    grant_id: str,
    grant_digest: str,
    action: str,
    amount: int,
    now: int,
    ttl: int,
) -> str:
    return _encode(key, PROOF_TYP, {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "grant": {"id": grant_id, "digest": grant_digest},
        "authorization_details": [{
            "type": ACTION_DETAIL_TYPE,
            "locations": [audience],
            "actions": [action],
            "amount": amount,
        }],
    })


# -- revocation event --------------------------------------------------------


def encode_revocation(
    key: SigningKey,
    *,
    issuer: str,
    audience: str,
    subject: str,
    grant_id: str,
    grant_digest: str,
    initiating_entity: str,
    revoked_at: int,
    now: int,
) -> str:
    return _encode(key, SET_TYP, {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "txn": grant_id,
        "sub_id": {"format": "opaque", "id": subject},
        "events": {
            EVENT_GRANT_REVOKED: {
                "grant_id": grant_id,
                "grant_digest": grant_digest,
                "event_timestamp": revoked_at,
                "initiating_entity": initiating_entity,
            },
        },
    })
