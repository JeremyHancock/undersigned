"""A software passkey for tests and demos. Not for production use."""

from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from undersigned.evidence import HumanEvidence
from undersigned.keys import b64url, b64url_decode

_FLAG_USER_PRESENT = 0x01
_FLAG_USER_VERIFIED = 0x04
_FLAG_ATTESTED_DATA = 0x40


class SoftAuthenticator:
    """Produces WebAuthn assertions the way a platform authenticator would."""

    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b64url(os.urandom(16))
        self._counter = 0

    @property
    def cose_public_key(self) -> bytes:
        """The credential public key as a COSE_Key (EC2, P-256, ES256)."""
        numbers = self._key.public_key().public_numbers()
        x = numbers.x.to_bytes(32, "big")
        y = numbers.y.to_bytes(32, "big")
        # CBOR map {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        return bytes([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]) + x + bytes(
            [0x22, 0x58, 0x20]
        ) + y

    def sign(
        self,
        challenge: bytes,
        *,
        rp_id: str,
        origin: str,
        user_verified: bool = True,
    ) -> HumanEvidence:
        self._counter += 1
        flags = _FLAG_USER_PRESENT | (_FLAG_USER_VERIFIED if user_verified else 0)
        authenticator_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags])
            + self._counter.to_bytes(4, "big")
        )
        client_data_json = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": b64url(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        signed = authenticator_data + hashlib.sha256(client_data_json).digest()
        signature = self._key.sign(signed, ec.ECDSA(hashes.SHA256()))
        return HumanEvidence(
            credential_id=self.credential_id,
            authenticator_data=b64url(authenticator_data),
            client_data_json=b64url(client_data_json),
            signature=b64url(signature),
        )

    def assertion(self, challenge: bytes, *, rp_id: str, origin: str) -> dict:
        """The JSON a browser gets back from ``navigator.credentials.get``."""
        evidence = self.sign(challenge, rp_id=rp_id, origin=origin)
        return {
            "id": self.credential_id,
            "rawId": self.credential_id,
            "type": "public-key",
            "response": {
                "authenticatorData": evidence.authenticator_data,
                "clientDataJSON": evidence.client_data_json,
                "signature": evidence.signature,
            },
        }

    def register(self, challenge: bytes, *, rp_id: str, origin: str) -> dict:
        """The JSON a browser gets back from ``navigator.credentials.create``.

        Uses the ``none`` attestation format, as most passkeys do.
        """
        credential_id = b64url_decode(self.credential_id)
        flags = _FLAG_USER_PRESENT | _FLAG_USER_VERIFIED | _FLAG_ATTESTED_DATA
        authenticator_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags])
            + (0).to_bytes(4, "big")
            + bytes(16)  # AAGUID
            + len(credential_id).to_bytes(2, "big")
            + credential_id
            + self.cose_public_key
        )
        # CBOR map {"fmt": "none", "attStmt": {}, "authData": <bytes>}
        attestation_object = (
            b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData"
            + b"\x59" + len(authenticator_data).to_bytes(2, "big") + authenticator_data
        )
        client_data_json = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": b64url(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return {
            "id": self.credential_id,
            "rawId": self.credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data_json),
                "attestationObject": b64url(attestation_object),
            },
        }
