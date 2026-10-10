# llm-sql-guard

Validate LLM-generated SQL against a policy before it reaches your database.

If you let a language model write SQL and then execute it, the model's output is
untrusted input. `llm-sql-guard` sits between generation and execution and decides
whether the query is allowed to run — based on the **parsed syntax tree**, not on
pattern-matching the query text.

```python
from llm_sql_guard import Policy, enforce, GuardError

policy = Policy(allowed_tables={"orders", "customers"}, max_limit=500)

try:
    sql = enforce(model_output, policy)
except GuardError as e:
    return f"I can't run that: {e}"

rows = connection.execute(sql)
```

## Why the AST and not a regex

Text-level checks are the usual first attempt, and they lose to ordinary SQL:

| Query | Regex guard | This guard |
|---|---|---|
| `SELECT ... WHERE name = 'DROP TABLE'` | rejects (false positive) | allows |
| `SELECT 1 -- ; DROP TABLE users` | rejects (false positive) | allows |
| `WITH g AS (DELETE FROM users RETURNING id) SELECT * FROM g` | allows (misses it) | **rejects** |
| `SELECT id FROM users WHERE id IN (SELECT x FROM secrets)` | allows (misses it) | **rejects** |

The third row is the one that matters. PostgreSQL really does execute a `DELETE`
written inside a CTE, and a check that only inspects the statement's first keyword
sees `WITH` and waves it through.

False positives matter as much as misses: a guard that blocks legitimate work gets
turned off, and then nothing is checked at all.

## What it checks

1. **Parses first.** A query that will not parse is rejected rather than forwarded
   in the hope the database rejects it safely.
2. **One statement only.** Stacked statements are how an injected payload runs.
3. **Read-only, by allowlist.** Only `SELECT` and set operations pass. Statement
   types are allowlisted, not denylisted, so a type nobody anticipated fails closed.
4. **Writes anywhere in the tree.** The whole AST is walked, so a write nested in a
   CTE or subquery is caught.
5. **Table allowlist, CTE-aware.** `WITH recent AS (...)` binds a name; `recent` is
   not a base table and is not required to be in the allowlist. Qualified names match
   a bare allowlist entry, so `analytics.events` satisfies `events`.
6. **Blocked functions.** Filesystem reads, network calls, configuration access, and
   time-based probes (`pg_sleep`, `pg_read_file`, `dblink`, `current_setting`, …) —
   the primitives that turn read access into exfiltration.
7. **Row limits.** A `LIMIT` can be required and capped.
8. **Dialect awareness.** Validating BigQuery SQL under the generic dialect raises a
   parse error on valid queries, which silently rejects good work. Pass the dialect
   the query was written for.

## Install

```bash
pip install llm-sql-guard
```

## Usage

### Inspect instead of raising

```python
from llm_sql_guard import check, Policy

result = check(sql, Policy(allowed_tables={"events"}))
if not result.ok:
    for v in result.violations:
        print(v.code, v.message)   # e.g. table_not_allowed  table 'secrets' is not in the allowlist
else:
    print(result.tables)           # {'events'}
```

`GuardResult` is falsy when rejected, so `if not check(sql, policy):` reads naturally.

### Policy options

```python
Policy(
    allowed_tables={"events"},      # empty set = nothing allowed (fails closed)
    max_limit=1000,
    require_limit=True,
    allow_subqueries=True,
    allow_joins=True,
    allow_set_operations=False,     # UNION is a common exfiltration shape
    dialect="bigquery",             # any sqlglot dialect
    max_query_length=20_000,
)
```

Policies are immutable; `policy.with_tables("orders")` and `policy.for_dialect("mysql")`
return modified copies.

### Violation codes

`empty`, `too_long`, `unparseable`, `multiple_statements`, `not_read_only`,
`nested_write`, `set_operation`, `join`, `subquery`, `no_table`, `table_not_allowed`,
`blocked_function`, `missing_limit`, `limit_too_high`.

Stable strings, safe to branch on.

## This is one layer, not the whole defence

Run the query as a database role that is physically incapable of doing what you are
trying to prevent — `SELECT` granted only on the tables in your allowlist. Then a bug
in this library is a defence-in-depth failure instead of a breach. Also set a statement
timeout, and log every query you execute.

A guard that is your only control is a guard you are trusting too much.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Licence

MIT
