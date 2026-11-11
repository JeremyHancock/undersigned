"""Exception types. Every error carries a stable machine-readable ``code``."""

from __future__ import annotations


class UndersignedError(Exception):
    """Base class for all undersigned errors."""

    code = "undersigned_error"

    def __init__(self, message: str = "", *, code: str | None = None):
        super().__init__(message or code or self.code)
        if code:
            self.code = code


class InvalidGrant(UndersignedError):
    """The grant document is malformed or breaks a structural rule."""

    code = "invalid_grant"


class EvidenceError(UndersignedError):
    """The human-signed evidence for a grant did not verify."""

    code = "invalid_evidence"


class SignatureError(UndersignedError):
    """An HTTP message signature or token signature did not verify."""

    code = "invalid_signature"


class Denied(UndersignedError):
    """The action is not authorized and human approval would not change that."""

    code = "denied"


class StepUpRequired(UndersignedError):
    """The standing grant does not cover this action; a human must approve it.

    ``code`` says why: ``action_not_covered``, ``risk_exceeds_grant``,
    ``first_use`` or ``budget_exceeded``.
    """

    code = "step_up_required"


class UnknownGrant(UndersignedError):
    """The service has not received the grant a proof refers to."""

    code = "unknown_grant"
