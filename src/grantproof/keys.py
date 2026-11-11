"""Broker signing keys (Ed25519) and the public key sets services verify with."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from grantproof.errors import SignatureError


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _public_jwk(public_key: Ed25519PublicKey) -> dict:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of an OKP key."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64url(hashlib.sha256(canonical).digest())


class SigningKey:
    """An Ed25519 private key. The key id is the RFC 7638 thumbprint."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key
        jwk = _public_jwk(private_key.public_key())
        self.kid = thumbprint(jwk)
        self._jwk = {**jwk, "kid": self.kid, "use": "sig", "alg": "EdDSA"}

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> "SigningKey":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("expected an Ed25519 private key")
        return cls(key)

    def to_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def public_jwk(self) -> dict:
        return dict(self._jwk)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


class KeySet:
    """Public keys by key id. Build it from the broker's JWKS document."""

    def __init__(self, keys: dict[str, Ed25519PublicKey] | None = None):
        self._keys = dict(keys or {})

    @classmethod
    def from_jwks(cls, document: dict) -> "KeySet":
        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in document.get("keys", []):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
            keys[jwk.get("kid") or thumbprint(jwk)] = public_key
        return cls(keys)

    @classmethod
    def of(cls, *signing_keys: SigningKey) -> "KeySet":
        return cls({key.kid: key.private_key.public_key() for key in signing_keys})

    def get(self, kid: str | None) -> Ed25519PublicKey:
        if not kid or kid not in self._keys:
            raise SignatureError("no key with that key id", code="unknown_key")
        return self._keys[kid]

    def verify(self, kid: str | None, signature: bytes, message: bytes) -> None:
        try:
            self.get(kid).verify(signature, message)
        except InvalidSignature as exc:
            raise SignatureError("signature does not match") from exc


def jwks(*signing_keys: SigningKey) -> dict:
    """The JWKS document a broker publishes."""
    return {"keys": [key.public_jwk() for key in signing_keys]}
