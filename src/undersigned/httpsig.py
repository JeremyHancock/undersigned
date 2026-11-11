"""Request binding: Content-Digest (RFC 9530) and HTTP Message Signatures (RFC 9421).

This is a deliberately small profile of RFC 9421, enough for a broker to sign
one request and a service to verify it:

* algorithm ``ed25519`` only;
* covered components are ``@method``, ``@target-uri``, ``@authority``, ``@path``
  and plain header fields (no component parameters);
* the parameters ``created``, ``expires``, ``keyid`` and ``tag`` are required.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from undersigned.errors import SignatureError
from undersigned.keys import KeySet, SigningKey

ALGORITHM = "ed25519"
DEFAULT_LABEL = "gp"


def content_digest(body: bytes) -> str:
    """The ``Content-Digest`` header value for ``body`` (SHA-256)."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") + ":"


@dataclass(frozen=True)
class SignatureInfo:
    keyid: str
    created: int
    expires: int
    nonce: str | None
    tag: str
    components: tuple[str, ...]


# -- signing -----------------------------------------------------------------


def sign_request(
    key: SigningKey,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    components: tuple[str, ...],
    created: int,
    expires: int,
    tag: str,
    label: str = DEFAULT_LABEL,
    nonce: str | None = None,
) -> dict[str, str]:
    """Return the ``Signature-Input`` and ``Signature`` headers for a request.

    ``headers`` must already contain every header field named in ``components``.
    """
    nonce = nonce or secrets.token_urlsafe(16)
    inner = "(" + " ".join(f'"{c}"' for c in components) + ")"
    params = (
        f'{inner};created={created};expires={expires};nonce="{nonce}"'
        f';keyid="{key.kid}";alg="{ALGORITHM}";tag="{tag}"'
    )
    base = _signature_base(components, params, method, url, headers)
    signature = base64.b64encode(key.sign(base)).decode("ascii")
    return {"Signature-Input": f"{label}={params}", "Signature": f"{label}=:{signature}:"}


# -- verification ------------------------------------------------------------


def verify_request(
    keys: KeySet,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    required_components: tuple[str, ...],
    tag: str,
    now: int,
    leeway: int = 5,
    max_lifetime: int = 300,
) -> SignatureInfo:
    """Verify the signature tagged ``tag`` and that it covers this exact request."""
    lowered = _lower(headers)
    inputs = _parse_dictionary(lowered.get("signature-input", ""))
    signatures = _parse_dictionary(lowered.get("signature", ""))

    chosen = None
    for label, raw in inputs.items():
        components, params = _parse_signature_params(raw)
        if params.get("tag") == tag:
            chosen = (label, raw, components, params)
            break
    if chosen is None:
        raise SignatureError(f"no signature tagged {tag!r}", code="signature_missing")
    label, raw, components, params = chosen

    missing = [c for c in required_components if c not in components]
    if missing:
        raise SignatureError(f"signature does not cover {missing}", code="signature_incomplete")
    if params.get("alg", ALGORITHM) != ALGORITHM:
        raise SignatureError("unsupported signature algorithm", code="unsupported_algorithm")
    keyid = params.get("keyid")
    created, expires = params.get("created"), params.get("expires")
    if not isinstance(keyid, str) or not isinstance(created, int) or not isinstance(expires, int):
        raise SignatureError("keyid, created and expires are required", code="signature_incomplete")
    if created > now + leeway:
        raise SignatureError("signature created in the future", code="signature_not_yet_valid")
    if now > expires + leeway:
        raise SignatureError("signature expired", code="signature_expired")
    if expires - created > max_lifetime:
        raise SignatureError("signature lifetime too long", code="signature_lifetime")

    if "content-digest" in components:
        _check_content_digest(lowered.get("content-digest", ""), body)

    raw_signature = signatures.get(label, "")
    if not (raw_signature.startswith(":") and raw_signature.endswith(":") and len(raw_signature) > 2):
        raise SignatureError("signature value missing", code="signature_missing")
    try:
        signature = base64.b64decode(raw_signature[1:-1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("signature is not valid base64") from exc

    base = _signature_base(components, raw, method, url, lowered)
    keys.verify(keyid, signature, base)
    nonce = params.get("nonce")
    return SignatureInfo(
        keyid=keyid,
        created=created,
        expires=expires,
        nonce=nonce if isinstance(nonce, str) else None,
        tag=tag,
        components=components,
    )


def _check_content_digest(header: str, body: bytes) -> None:
    entries = _parse_dictionary(header)
    value = entries.get("sha-256", "")
    if not (value.startswith(":") and value.endswith(":")):
        raise SignatureError("Content-Digest has no sha-256 value", code="digest_missing")
    try:
        claimed = base64.b64decode(value[1:-1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("Content-Digest is not valid base64", code="digest_mismatch") from exc
    if not hmac.compare_digest(claimed, hashlib.sha256(body).digest()):
        raise SignatureError("body does not match Content-Digest", code="digest_mismatch")


# -- signature base ----------------------------------------------------------


def _signature_base(
    components: tuple[str, ...],
    signature_params: str,
    method: str,
    url: str,
    headers: Mapping[str, str],
) -> bytes:
    lowered = _lower(headers)
    lines = []
    seen = set()
    for component in components:
        if component in seen:
            raise SignatureError("duplicate covered component", code="signature_malformed")
        seen.add(component)
        if component == "@method":
            value = method
        elif component == "@target-uri":
            value = url
        elif component == "@authority":
            value = _authority(url)
        elif component == "@path":
            value = urlsplit(url).path or "/"
        elif component.startswith("@"):
            raise SignatureError(f"unsupported component {component}", code="signature_malformed")
        else:
            if component not in lowered:
                raise SignatureError(f"header {component} is absent", code="signature_incomplete")
            value = lowered[component].strip()
        if "\n" in value or "\r" in value:
            raise SignatureError("component value contains a line break", code="signature_malformed")
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {signature_params}')
    try:
        return "\n".join(lines).encode("ascii")
    except UnicodeEncodeError as exc:
        raise SignatureError("signature base must be ASCII", code="signature_malformed") from exc


def _authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    if parts.port is not None and parts.port != default:
        return f"{host}:{parts.port}"
    return host


def _lower(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(name).lower(): str(value) for name, value in headers.items()}


# -- minimal structured-field parsing (RFC 8941) -----------------------------


def _parse_dictionary(text: str) -> dict[str, str]:
    """Split a Dictionary header into ``{key: raw member value}``."""
    members: dict[str, str] = {}
    for member in _split_top_level(text, ","):
        member = member.strip()
        if not member:
            continue
        key, _, value = member.partition("=")
        members[key.strip()] = value.strip()
    return members


def _split_top_level(text: str, separator: str) -> list[str]:
    parts, current, in_string, escaped = [], [], False, False
    for char in text:
        if in_string:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            current.append(char)
        elif char == separator:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if in_string:
        raise SignatureError("unterminated string in header", code="signature_malformed")
    parts.append("".join(current))
    return parts


def _parse_signature_params(raw: str) -> tuple[tuple[str, ...], dict[str, object]]:
    """Parse ``("a" "b");created=1;keyid="k"`` into components and parameters."""
    if not raw.startswith("("):
        raise SignatureError("Signature-Input is not an inner list", code="signature_malformed")
    close = raw.find(")")
    if close < 0:
        raise SignatureError("Signature-Input is not an inner list", code="signature_malformed")
    components = []
    for item in raw[1:close].split():
        if not (item.startswith('"') and item.endswith('"') and len(item) >= 2):
            raise SignatureError("unsupported covered component", code="signature_malformed")
        components.append(item[1:-1])
    params: dict[str, object] = {}
    for piece in _split_top_level(raw[close + 1:], ";"):
        piece = piece.strip()
        if not piece:
            continue
        name, _, value = piece.partition("=")
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            params[name] = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        elif re.fullmatch(r"-?[0-9]{1,15}", value):
            params[name] = int(value)
        else:
            params[name] = value
    return tuple(components), params
