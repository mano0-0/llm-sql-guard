"""Validate LLM-generated SQL before it reaches your database."""

from .guard import GuardError, GuardResult, Violation, check, enforce
from .policy import DEFAULT_BLOCKED_FUNCTIONS, Policy, PolicyError

__version__ = "0.1.0"

__all__ = [
    "Policy",
    "PolicyError",
    "DEFAULT_BLOCKED_FUNCTIONS",
    "check",
    "enforce",
    "GuardResult",
    "GuardError",
    "Violation",
    "__version__",
]
