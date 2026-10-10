"""Validate LLM-generated SQL against a policy before it reaches a database.

The checks are ordered cheapest-first, and every one of them operates on the
parsed AST rather than on the query text. Text-level scanning is easy to defeat
with comments, string literals, or unusual whitespace; the AST is what the
database will actually execute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set

import sqlglot
from sqlglot import exp

from .policy import Policy

# Statement types that read data. Anything else is rejected outright rather
# than enumerated as "dangerous" -- an allowlist cannot be outflanked by a
# statement type that did not exist when this was written.
_READ_ONLY_STATEMENTS = (exp.Select, exp.Union, exp.Except, exp.Intersect)

_SET_OPERATIONS = (exp.Union, exp.Except, exp.Intersect)


class GuardError(Exception):
    """Raised by :func:`enforce` when a query violates the policy."""

    def __init__(self, violations: Sequence["Violation"]) -> None:
        self.violations = list(violations)
        detail = "; ".join(v.message for v in self.violations)
        super().__init__(f"query rejected: {detail}")


@dataclass(frozen=True)
class Violation:
    """A single reason a query was rejected."""

    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.code}] {self.message}"


@dataclass
class GuardResult:
    """Outcome of validating one query."""

    ok: bool
    violations: List[Violation] = field(default_factory=list)
    sql: Optional[str] = None
    tables: Set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return self.ok

    @property
    def reasons(self) -> List[str]:
        return [v.message for v in self.violations]


def _cte_names(tree: exp.Expression) -> Set[str]:
    """Names bound by WITH clauses anywhere in the tree.

    These are *not* base tables. Treating them as such would reject a
    perfectly legal query whose CTE happens to be named something not in the
    allowlist, which is the most common false positive in this kind of check.
    """
    names: Set[str] = set()
    for cte in tree.find_all(exp.CTE):
        alias = cte.alias_or_name
        if alias:
            names.add(alias.lower())
    return names


def _referenced_tables(tree: exp.Expression) -> Set[str]:
    """Base tables referenced by the query, excluding CTE self-references."""
    bound = _cte_names(tree)
    tables: Set[str] = set()
    for node in tree.find_all(exp.Table):
        name = node.name
        if not name:
            continue
        name = name.lower()
        if name in bound:
            continue
        # Qualified names (schema.table) are compared on the full path too,
        # so a policy may allow either "events" or "analytics.events".
        db = (node.text("db") or "").lower()
        catalog = (node.text("catalog") or "").lower()
        qualified = ".".join(p for p in (catalog, db, name) if p)
        tables.add(qualified if qualified else name)
    return tables


def _called_functions(tree: exp.Expression) -> Set[str]:
    """Lowercased names of every function invoked in the query."""
    found: Set[str] = set()
    for node in tree.find_all(exp.Func):
        name = node.sql_name() if hasattr(node, "sql_name") else None
        if name:
            found.add(name.lower())
        # Anonymous functions carry the parsed identifier in `this`.
        this = node.args.get("this")
        if isinstance(this, str):
            found.add(this.lower())
    return found


def _effective_limit(tree: exp.Expression) -> Optional[int]:
    """The query's outermost LIMIT, if it is a literal integer."""
    limit = tree.args.get("limit")
    if limit is None and isinstance(tree, _SET_OPERATIONS):
        return None
    if limit is None:
        return None
    value = limit.expression if isinstance(limit, exp.Limit) else limit
    if isinstance(value, exp.Literal) and value.is_int:
        try:
            return int(value.name)
        except (TypeError, ValueError):
            return None
    return None


def _strip_trailing_semicolon(sql: str) -> str:
    return re.sub(r";\s*$", "", sql.strip())


def check(sql: str, policy: Policy) -> GuardResult:
    """Validate ``sql`` against ``policy``. Never raises on invalid SQL."""
    violations: List[Violation] = []

    if not sql or not sql.strip():
        return GuardResult(False, [Violation("empty", "query is empty")])

    if len(sql) > policy.max_query_length:
        return GuardResult(
            False,
            [Violation(
                "too_long",
                f"query is {len(sql)} characters, limit is {policy.max_query_length}",
            )],
        )

    # Parse before anything else. A query that will not parse cannot be
    # reasoned about, and must never be forwarded on the assumption that the
    # database will reject it safely.
    try:
        statements = sqlglot.parse(sql, dialect=policy.dialect)
    except Exception as exc:  # sqlglot raises several distinct error types
        return GuardResult(
            False, [Violation("unparseable", f"could not parse SQL: {exc}")]
        )

    statements = [s for s in statements if s is not None]

    if not statements:
        return GuardResult(False, [Violation("empty", "query contains no statement")])

    # Multiple statements are how a stacked-query injection executes its
    # payload. One request means one statement.
    if len(statements) > 1:
        return GuardResult(
            False,
            [Violation(
                "multiple_statements",
                f"expected a single statement, found {len(statements)}",
            )],
        )

    tree = statements[0]

    if not isinstance(tree, _READ_ONLY_STATEMENTS):
        kind = type(tree).__name__.upper()
        return GuardResult(
            False,
            [Violation("not_read_only", f"only read queries are allowed, found {kind}")],
        )

    if isinstance(tree, _SET_OPERATIONS) and not policy.allow_set_operations:
        violations.append(
            Violation("set_operation", "set operations (UNION/EXCEPT/INTERSECT) are not allowed")
        )

    # A write nested inside a CTE or subquery still writes. Walk the whole
    # tree rather than trusting the type of the root node.
    for node in tree.walk():
        if isinstance(node, (exp.Insert, exp.Update, exp.Delete, exp.Drop,
                             exp.Create, exp.Alter, exp.TruncateTable)):
            violations.append(
                Violation(
                    "nested_write",
                    f"write operation {type(node).__name__.upper()} found inside the query",
                )
            )
            break

    if not policy.allow_joins and list(tree.find_all(exp.Join)):
        violations.append(Violation("join", "joins are not allowed by this policy"))

    if not policy.allow_subqueries:
        if list(tree.find_all(exp.Subquery)) or list(tree.find_all(exp.CTE)):
            violations.append(
                Violation("subquery", "subqueries and CTEs are not allowed by this policy")
            )

    tables = _referenced_tables(tree)
    if not tables:
        violations.append(
            Violation("no_table", "query references no table")
        )
    else:
        # Compare on the bare name too, so "analytics.events" satisfies an
        # allowlist entry of "events".
        for t in sorted(tables):
            bare = t.rsplit(".", 1)[-1]
            if t not in policy.allowed_tables and bare not in policy.allowed_tables:
                violations.append(
                    Violation("table_not_allowed", f"table {t!r} is not in the allowlist")
                )

    blocked = _called_functions(tree) & policy.blocked_functions
    for fn in sorted(blocked):
        violations.append(
            Violation("blocked_function", f"function {fn}() is not permitted")
        )

    limit = _effective_limit(tree)
    if limit is None:
        if policy.require_limit:
            violations.append(
                Violation("missing_limit", f"query must declare LIMIT <= {policy.max_limit}")
            )
    elif limit > policy.max_limit:
        violations.append(
            Violation("limit_too_high", f"LIMIT {limit} exceeds maximum of {policy.max_limit}")
        )

    ok = not violations
    return GuardResult(
        ok=ok,
        violations=violations,
        sql=_strip_trailing_semicolon(sql) if ok else None,
        tables=tables,
    )


def enforce(sql: str, policy: Policy) -> str:
    """Validate ``sql`` and return it, or raise :class:`GuardError`.

    Use this at the call site where the query would otherwise be executed, so
    that a violation cannot be ignored by forgetting to inspect a result.
    """
    result = check(sql, policy)
    if not result.ok:
        raise GuardError(result.violations)
    assert result.sql is not None
    return result.sql
