"""Envelope evaluation, shared by the broker and the service.

Both sides run the same function over the same grant, each against its own
state. That is what makes the result jointly verified: the service does not
take the broker's word that an action fits the envelope.
"""

from __future__ import annotations

from dataclasses import dataclass

from grantproof.grant import BUDGET_PERIODS, Grant, risk_rank

ALLOW = "allow"
STEP_UP = "step_up"
DENY = "deny"


@dataclass
class GrantState:
    """Mutable facts about a grant that one party tracks."""

    revoked: bool = False
    first_use_confirmed: bool = False
    uses: int = 0
    spent: int = 0
    period_start: int | None = None


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome == ALLOW


def _period_start(grant: Grant, now: int) -> int | None:
    if grant.budget is None:
        return None
    length = BUDGET_PERIODS[grant.budget.period]
    if length is None:
        return grant.issued_at
    return grant.issued_at + ((now - grant.issued_at) // length) * length


def spent_this_period(grant: Grant, state: GrantState, now: int) -> int:
    """Spend counted against the current budget window."""
    if state.period_start != _period_start(grant, now):
        return 0
    return state.spent


def evaluate(
    grant: Grant,
    state: GrantState,
    *,
    action: str,
    risk: str,
    amount: int = 0,
    now: int,
    content_digest: str | None = None,
    enforce_first_use: bool = True,
    leeway: int = 0,
) -> Decision:
    """Decide whether ``action`` fits inside ``grant`` right now.

    ``deny`` means no approval under this grant can help (revoked, expired,
    used up). ``step_up`` means the standing envelope does not cover the action
    and the human has to approve it individually.
    """
    if state.revoked:
        return Decision(DENY, "grant_revoked")
    if now + leeway < grant.issued_at:
        return Decision(DENY, "grant_not_yet_valid")
    if now >= grant.expires_at:
        return Decision(DENY, "grant_expired")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        return Decision(DENY, "invalid_amount")
    if grant.single_use and state.uses >= 1:
        return Decision(DENY, "grant_already_used")

    if action not in grant.actions:
        return Decision(STEP_UP, "action_not_covered")
    if risk_rank(risk) > risk_rank(grant.max_risk):
        return Decision(STEP_UP, "risk_exceeds_grant")
    if grant.content_digest is not None and content_digest != grant.content_digest:
        return Decision(DENY, "request_does_not_match_grant")
    if enforce_first_use and grant.first_use_confirmation and not state.first_use_confirmed:
        return Decision(STEP_UP, "first_use")
    if grant.budget is not None:
        if spent_this_period(grant, state, now) + amount > grant.budget.limit:
            return Decision(STEP_UP, "budget_exceeded")
    return Decision(ALLOW)


def record_use(grant: Grant, state: GrantState, *, amount: int = 0, now: int) -> None:
    """Record an allowed action against the grant's counters."""
    start = _period_start(grant, now)
    if state.period_start != start:
        state.period_start = start
        state.spent = 0
    state.spent += amount
    state.uses += 1
