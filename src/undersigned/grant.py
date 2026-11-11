"""The grant: what a human authorized, in a form they can sign.

A grant is either *standing* (an envelope the agent may act inside without
further prompts) or *single-use* (one approval for one action, used when an
action punches through a standing grant). The document form carries the
envelope as an RFC 9396 ``authorization_details`` object, and its RFC 8785
digest is what the human's authenticator signs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from undersigned import jcs
from undersigned.errors import InvalidGrant

GRANT_VERSION = "1"
DETAIL_TYPE = "urn:undersigned:grant:v1"

RISK_TIERS = ("low", "medium", "high", "critical")
#: The highest risk tier a standing grant may cover. Anything above always
#: needs its own single-use approval.
STANDING_RISK_CEILING = "medium"

_MAX_INT = 2**53 - 1  # largest integer JSON carries safely (RFC 8785)

BUDGET_PERIODS = {"day": 86_400, "week": 7 * 86_400, "month": 30 * 86_400, "total": None}


def risk_rank(tier: str) -> int:
    try:
        return RISK_TIERS.index(tier)
    except ValueError as exc:
        raise InvalidGrant(f"unknown risk tier: {tier!r}") from exc


@dataclass(frozen=True)
class Budget:
    """A spending cap in integer minor units of ``unit`` per ``period``.

    Periods are fixed windows counted from the grant's ``issued_at``.
    """

    limit: int
    unit: str
    period: str = "month"

    def __post_init__(self):
        if (isinstance(self.limit, bool) or not isinstance(self.limit, int)
                or not 0 <= self.limit <= _MAX_INT):
            raise InvalidGrant("budget limit must be a non-negative integer")
        if not self.unit or not isinstance(self.unit, str):
            raise InvalidGrant("budget unit is required")
        if self.period not in BUDGET_PERIODS:
            raise InvalidGrant(f"unknown budget period: {self.period!r}")


@dataclass(frozen=True)
class PinnedRequest:
    """One exact HTTP request: its method, absolute URL and body digest.

    A single-use grant carrying this can authorize that request and no other.
    ``content_digest`` is an RFC 9530 ``Content-Digest`` value.
    """

    method: str
    target_uri: str
    content_digest: str

    def __post_init__(self):
        for name in ("method", "target_uri", "content_digest"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise InvalidGrant(f"pinned request {name} must be a non-empty string")

    @classmethod
    def of(cls, method: str, url: str, body: bytes) -> "PinnedRequest":
        from undersigned.httpsig import content_digest  # avoids an import cycle

        return cls(method=method, target_uri=url, content_digest=content_digest(body))


@dataclass(frozen=True)
class Grant:
    issuer: str  #: the broker that brokered the approval
    audience: str  #: the service the grant is for
    subject: str  #: the human's account id at the service
    actions: tuple[str, ...]
    issued_at: int
    expires_at: int
    max_risk: str = "low"
    budget: Budget | None = None
    first_use_confirmation: bool = False
    single_use: bool = False
    #: Single-use grants may be pinned to one exact request.
    request: PinnedRequest | None = None
    grant_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        object.__setattr__(self, "actions", tuple(self.actions))
        for name in ("issuer", "audience", "subject", "grant_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise InvalidGrant(f"{name} is required")
        if not self.actions or not all(isinstance(a, str) and a for a in self.actions):
            raise InvalidGrant("at least one action is required")
        if len(set(self.actions)) != len(self.actions):
            raise InvalidGrant("actions must be unique")
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_INT:
                raise InvalidGrant(f"{name} must be an integer timestamp")
        if self.expires_at <= self.issued_at:
            raise InvalidGrant("expires_at must be after issued_at")
        risk_rank(self.max_risk)
        if self.single_use:
            if len(self.actions) != 1:
                raise InvalidGrant("a single-use grant covers exactly one action")
            if self.first_use_confirmation:
                raise InvalidGrant("first-use confirmation does not apply to single-use grants")
        else:
            if risk_rank(self.max_risk) > risk_rank(STANDING_RISK_CEILING):
                raise InvalidGrant(
                    f"a standing grant cannot cover risk above {STANDING_RISK_CEILING!r}"
                )
            if self.request is not None:
                raise InvalidGrant("only single-use grants can be pinned to a request")
        if self.request is not None and not isinstance(self.request, PinnedRequest):
            raise InvalidGrant("request must be a PinnedRequest")

    # -- document form -----------------------------------------------------

    def to_document(self) -> dict:
        detail: dict = {
            "type": DETAIL_TYPE,
            "locations": [self.audience],
            "actions": list(self.actions),
            "max_risk": self.max_risk,
            "single_use": self.single_use,
            "first_use_confirmation": self.first_use_confirmation,
        }
        if self.budget is not None:
            detail["budget"] = {
                "limit": self.budget.limit,
                "unit": self.budget.unit,
                "period": self.budget.period,
            }
        if self.request is not None:
            detail["request"] = {
                "method": self.request.method,
                "target_uri": self.request.target_uri,
                "content_digest": self.request.content_digest,
            }
        return {
            "version": GRANT_VERSION,
            "grant_id": self.grant_id,
            "iss": self.issuer,
            "aud": self.audience,
            "sub_id": {"format": "opaque", "id": self.subject},
            "iat": self.issued_at,
            "exp": self.expires_at,
            "authorization_details": [detail],
        }

    @classmethod
    def from_document(cls, document: dict) -> "Grant":
        """Parse a grant document strictly: unknown fields are an error.

        Strictness matters because the digest covers the whole document; a
        field this code ignored would still be something the human signed.
        """
        try:
            _expect_keys(document, {"version", "grant_id", "iss", "aud", "sub_id", "iat", "exp",
                                    "authorization_details"})
            if document["version"] != GRANT_VERSION:
                raise InvalidGrant(f"unsupported grant version: {document['version']!r}")
            sub_id = document["sub_id"]
            _expect_keys(sub_id, {"format", "id"})
            if sub_id["format"] != "opaque":
                raise InvalidGrant("sub_id format must be 'opaque'")
            details = document["authorization_details"]
            if not isinstance(details, list) or len(details) != 1:
                raise InvalidGrant("exactly one authorization_details object is required")
            detail = details[0]
            _expect_keys(
                detail,
                {"type", "locations", "actions", "max_risk", "single_use",
                 "first_use_confirmation"},
                optional={"budget", "request"},
            )
            if detail["type"] != DETAIL_TYPE:
                raise InvalidGrant(f"unsupported authorization_details type: {detail['type']!r}")
            if detail["locations"] != [document["aud"]]:
                raise InvalidGrant("locations must be exactly the audience")
            for flag in ("single_use", "first_use_confirmation"):
                if not isinstance(detail[flag], bool):
                    raise InvalidGrant(f"{flag} must be a boolean")
            if not isinstance(detail["actions"], list):
                raise InvalidGrant("actions must be a list")
            budget = None
            if "budget" in detail:
                _expect_keys(detail["budget"], {"limit", "unit", "period"})
                budget = Budget(**detail["budget"])
            request = None
            if "request" in detail:
                _expect_keys(detail["request"], {"method", "target_uri", "content_digest"})
                request = PinnedRequest(**detail["request"])
            return cls(
                grant_id=document["grant_id"],
                issuer=document["iss"],
                audience=document["aud"],
                subject=sub_id["id"],
                actions=tuple(detail["actions"]),
                issued_at=document["iat"],
                expires_at=document["exp"],
                max_risk=detail["max_risk"],
                budget=budget,
                first_use_confirmation=detail["first_use_confirmation"],
                single_use=detail["single_use"],
                request=request,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise InvalidGrant(f"malformed grant document: {exc}") from exc

    # -- digest ------------------------------------------------------------

    def digest(self) -> bytes:
        """SHA-256 of the canonical document. This is the WebAuthn challenge."""
        try:
            return jcs.digest(self.to_document())
        except ValueError as exc:
            raise InvalidGrant(f"grant cannot be canonicalized: {exc}") from exc

    def digest_hex(self) -> str:
        return self.digest().hex()


def _expect_keys(obj, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(obj, dict):
        raise InvalidGrant("expected a JSON object")
    keys = set(obj)
    missing = required - keys
    extra = keys - required - (optional or set())
    if missing:
        raise InvalidGrant(f"missing field(s): {sorted(missing)}")
    if extra:
        raise InvalidGrant(f"unexpected field(s): {sorted(extra)}")
