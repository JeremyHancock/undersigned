"""Human-signed evidence for a grant: a WebAuthn assertion over its digest.

The broker runs an ordinary passkey ceremony with the grant digest as the
challenge and keeps the raw assertion. Anyone holding the credential's public
key can later check that this authenticator, with user verification, signed
exactly this grant. The broker's own signing key cannot produce one.
"""

from __future__ import annotations

from dataclasses import dataclass

from webauthn import verify_authentication_response

from grantproof.errors import EvidenceError
from grantproof.keys import b64url, b64url_decode

EVIDENCE_TYPE = "webauthn"


@dataclass(frozen=True)
class HumanEvidence:
    """A stored WebAuthn assertion. All fields are base64url without padding."""

    credential_id: str
    authenticator_data: str
    client_data_json: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "type": EVIDENCE_TYPE,
            "credential_id": self.credential_id,
            "authenticator_data": self.authenticator_data,
            "client_data_json": self.client_data_json,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HumanEvidence":
        try:
            if data["type"] != EVIDENCE_TYPE:
                raise EvidenceError(f"unsupported evidence type: {data['type']!r}")
            fields = {
                name: data[name]
                for name in ("credential_id", "authenticator_data", "client_data_json", "signature")
            }
        except (KeyError, TypeError) as exc:
            raise EvidenceError(f"malformed evidence: {exc}") from exc
        if not all(isinstance(v, str) and v for v in fields.values()):
            raise EvidenceError("evidence fields must be non-empty strings")
        return cls(**fields)

    @classmethod
    def from_assertion(cls, credential: dict) -> "HumanEvidence":
        """Build from the JSON a browser returns from ``navigator.credentials.get``."""
        response = credential["response"]
        return cls(
            credential_id=credential["id"],
            authenticator_data=response["authenticatorData"],
            client_data_json=response["clientDataJSON"],
            signature=response["signature"],
        )


def verify_evidence(
    evidence: HumanEvidence,
    *,
    challenge: bytes,
    rp_id: str,
    origin: str,
    credential_public_key: bytes,
) -> None:
    """Check the assertion signed ``challenge`` for ``rp_id`` with user verification.

    ``credential_public_key`` is the COSE key recorded when the passkey was
    registered. Signature counters are not checked: this verifies a stored
    assertion after the fact, not a live login.
    """
    credential = {
        "id": evidence.credential_id,
        "rawId": evidence.credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": evidence.authenticator_data,
            "clientDataJSON": evidence.client_data_json,
            "signature": evidence.signature,
        },
    }
    try:
        verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except Exception as exc:  # py_webauthn raises several unrelated types
        raise EvidenceError(f"assertion did not verify: {exc}") from exc


__all__ = ["EVIDENCE_TYPE", "HumanEvidence", "verify_evidence", "b64url", "b64url_decode"]
