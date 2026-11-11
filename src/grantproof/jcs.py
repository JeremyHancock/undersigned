"""JSON Canonicalization Scheme (RFC 8785), restricted to the types grants use.

Floats are rejected rather than serialized: RFC 8785 number formatting follows
ECMAScript, and amounts in this library are integers in minor units, so there
is no reason to take on that risk. Integers must fit in an IEEE double.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_MAX_SAFE_INT = 2**53 - 1


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    return _encode(value).encode("utf-8")


def digest(value: Any) -> bytes:
    """SHA-256 over the canonical encoding."""
    return hashlib.sha256(canonicalize(value)).digest()


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError("integer outside the interoperable JSON range")
        return str(value)
    if isinstance(value, float):
        raise ValueError("floats are not allowed; use integers in minor units")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
        # RFC 8785 §3.2.3: sort by UTF-16 code units, not code points.
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_encode_string(k) + ":" + _encode(value[k]) for k in keys) + "}"
    raise ValueError(f"unsupported type: {type(value).__name__}")


def _encode_string(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("string contains a lone surrogate") from exc
    # json.dumps with ensure_ascii=False matches the ECMAScript escaping that
    # RFC 8785 requires: short escapes for \b \f \n \r \t, lowercase \u00xx for
    # other control characters, and nothing else escaped but quote and backslash.
    return json.dumps(text, ensure_ascii=False)
