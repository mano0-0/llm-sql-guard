"""Policy objects describing what a generated query is allowed to do."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import FrozenSet, Optional

# Functions that read the filesystem, open network connections, or let an
# attacker measure response time. None of them have a legitimate place in a
# read-only analytics query, and several are the standard primitives for
# turning SELECT access into data exfiltration.
DEFAULT_BLOCKED_FUNCTIONS: FrozenSet[str] = frozenset({
    # time-based probing
    "pg_sleep", "sleep", "waitfor", "benchmark",
    # filesystem
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export", "load_file",
    # network / cross-database
    "dblink", "dblink_exec", "postgres_fdw_disconnect",
    # configuration and secret surface
    "current_setting", "set_config", "pg_read_server_files",
    # command execution surfaces seen in other engines
    "xp_cmdshell", "sp_executesql", "shell", "system",
})


class PolicyError(ValueError):
    """Raised when a policy is self-contradictory."""


@dataclass(frozen=True)
class Policy:
    """Declarative description of an acceptable query.

    The defaults are deliberately strict: an empty ``allowed_tables`` means
    *no* table may be referenced, so forgetting to configure the allowlist
    fails closed rather than open.
    """

    allowed_tables: FrozenSet[str] = frozenset()
    max_limit: int = 1000
    require_limit: bool = True
    allow_subqueries: bool = True
    allow_joins: bool = True
    allow_set_operations: bool = False
    blocked_functions: FrozenSet[str] = DEFAULT_BLOCKED_FUNCTIONS
    max_query_length: int = 20_000
    dialect: Optional[str] = None

    def __post_init__(self) -> None:
        if self.max_limit < 1:
            raise PolicyError("max_limit must be at least 1")
        if self.max_query_length < 1:
            raise PolicyError("max_query_length must be at least 1")
        # Normalise case once, so comparisons downstream are plain lookups.
        object.__setattr__(
            self, "allowed_tables", frozenset(t.lower() for t in self.allowed_tables)
        )
        object.__setattr__(
            self, "blocked_functions",
            frozenset(f.lower() for f in self.blocked_functions),
        )

    def with_tables(self, *tables: str) -> "Policy":
        """Return a copy of this policy with an extended table allowlist."""
        return replace(self, allowed_tables=self.allowed_tables | frozenset(tables))

    def for_dialect(self, dialect: str) -> "Policy":
        """Return a copy of this policy bound to a specific SQL dialect."""
        return replace(self, dialect=dialect)
