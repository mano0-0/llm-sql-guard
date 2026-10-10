"""Behavioural tests, grouped by the property each group defends."""

import pytest

from llm_sql_guard import GuardError, Policy, check, enforce

POLICY = Policy(
    allowed_tables={"events", "users", "analytics.sales"},
    max_limit=1000,
)


def codes(sql, policy=POLICY):
    return {v.code for v in check(sql, policy).violations}


# --------------------------------------------------------------------------
# Queries that must be allowed. A guard that rejects legitimate work gets
# switched off, so these matter as much as the attack cases.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT id, name FROM users LIMIT 10",
    "SELECT * FROM events WHERE created_at > '2024-01-01' LIMIT 100",
    "SELECT COUNT(*) AS n FROM events GROUP BY kind LIMIT 50",
    "SELECT u.id FROM users u JOIN events e ON e.user_id = u.id LIMIT 25",
    "WITH recent AS (SELECT * FROM events LIMIT 10) SELECT * FROM recent LIMIT 5",
    "SELECT * FROM analytics.sales LIMIT 1000",
    "select id from users limit 1",
    "SELECT id FROM users LIMIT 10;",
])
def test_allows_legitimate_reads(sql):
    result = check(sql, POLICY)
    assert result.ok, result.reasons


def test_cte_name_is_not_treated_as_a_base_table():
    # `recent` is bound by the WITH clause and is not in the allowlist.
    # Rejecting it would be a false positive.
    sql = "WITH recent AS (SELECT id FROM users LIMIT 10) SELECT id FROM recent LIMIT 10"
    assert check(sql, POLICY).ok


def test_qualified_name_matches_bare_allowlist_entry():
    policy = Policy(allowed_tables={"events"}, max_limit=10)
    assert check("SELECT * FROM warehouse.events LIMIT 5", policy).ok


def test_result_reports_the_tables_it_found():
    result = check("SELECT * FROM users JOIN events ON TRUE LIMIT 10", POLICY)
    assert result.tables == {"users", "events"}


# --------------------------------------------------------------------------
# Statement type: only reads.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "DELETE FROM users",
    "DROP TABLE users",
    "UPDATE users SET admin = true",
    "INSERT INTO users (id) VALUES (1)",
    "TRUNCATE TABLE events",
    "CREATE TABLE t (id INT)",
    "ALTER TABLE users ADD COLUMN x INT",
])
def test_rejects_write_statements(sql):
    assert "not_read_only" in codes(sql)


def test_rejects_write_nested_in_a_cte():
    # Postgres genuinely executes this. A check that only looked at the root
    # node would see a SELECT and wave it through.
    sql = ("WITH gone AS (DELETE FROM users RETURNING id) "
           "SELECT * FROM gone LIMIT 10")
    assert not check(sql, POLICY).ok


# --------------------------------------------------------------------------
# Injection shapes.
# --------------------------------------------------------------------------

def test_rejects_stacked_statements():
    assert "multiple_statements" in codes("SELECT 1 FROM users LIMIT 1; DROP TABLE users")


def test_rejects_union_against_a_disallowed_table():
    sql = "SELECT id FROM users UNION SELECT password FROM secrets LIMIT 10"
    found = codes(sql)
    assert "set_operation" in found or "table_not_allowed" in found


def test_comment_cannot_smuggle_a_second_statement():
    # The comment is discarded by the parser, so what remains is a single
    # ordinary SELECT. The point is that it is judged on the parsed form.
    result = check("SELECT id FROM users LIMIT 10 -- ; DROP TABLE users", POLICY)
    assert result.ok


def test_keyword_inside_a_string_literal_is_not_a_write():
    # A text-matching guard would reject this; an AST-based one should not.
    assert check("SELECT id FROM users WHERE name = 'DROP TABLE' LIMIT 10", POLICY).ok


# --------------------------------------------------------------------------
# Table allowlist.
# --------------------------------------------------------------------------

def test_rejects_table_outside_the_allowlist():
    assert "table_not_allowed" in codes("SELECT * FROM secrets LIMIT 10")


def test_rejects_disallowed_table_hidden_in_a_subquery():
    sql = ("SELECT id FROM users WHERE id IN "
           "(SELECT user_id FROM secrets) LIMIT 10")
    assert "table_not_allowed" in codes(sql)


def test_empty_allowlist_fails_closed():
    assert not check("SELECT * FROM users LIMIT 1", Policy()).ok


# --------------------------------------------------------------------------
# Blocked functions.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT pg_sleep(10) FROM users LIMIT 1",
    "SELECT pg_read_file('/etc/passwd') FROM users LIMIT 1",
    "SELECT current_setting('is_superuser') FROM users LIMIT 1",
    "SELECT lo_import('/etc/passwd') FROM users LIMIT 1",
])
def test_rejects_dangerous_functions(sql):
    assert "blocked_function" in codes(sql)


def test_ordinary_functions_are_untouched():
    assert check("SELECT UPPER(name), COUNT(*) FROM users GROUP BY 1 LIMIT 10", POLICY).ok


# --------------------------------------------------------------------------
# Row limits.
# --------------------------------------------------------------------------

def test_requires_a_limit_by_default():
    assert "missing_limit" in codes("SELECT * FROM users")


def test_rejects_a_limit_above_the_maximum():
    assert "limit_too_high" in codes("SELECT * FROM users LIMIT 100000")


def test_limit_may_be_optional():
    policy = Policy(allowed_tables={"users"}, require_limit=False)
    assert check("SELECT * FROM users", policy).ok


# --------------------------------------------------------------------------
# Malformed input.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sql", ["", "   ", "\n"])
def test_rejects_empty_input(sql):
    assert "empty" in codes(sql)


def test_rejects_unparseable_sql_rather_than_forwarding_it():
    assert "unparseable" in codes("SELECT FROM WHERE ((((")


def test_rejects_a_query_over_the_length_cap():
    policy = Policy(allowed_tables={"users"}, max_query_length=32)
    assert "too_long" in codes("SELECT " + ("a, " * 50) + "b FROM users LIMIT 1", policy)


# --------------------------------------------------------------------------
# Policy options and the enforce() entry point.
# --------------------------------------------------------------------------

def test_joins_can_be_disallowed():
    policy = Policy(allowed_tables={"users", "events"}, allow_joins=False)
    sql = "SELECT u.id FROM users u JOIN events e ON e.user_id = u.id LIMIT 10"
    assert "join" in {v.code for v in check(sql, policy).violations}


def test_subqueries_can_be_disallowed():
    policy = Policy(allowed_tables={"users"}, allow_subqueries=False)
    sql = "SELECT id FROM users WHERE id IN (SELECT id FROM users) LIMIT 10"
    assert "subquery" in {v.code for v in check(sql, policy).violations}


def test_dialect_specific_sql_parses_under_its_own_dialect():
    # BigQuery backtick quoting is a parse error for the generic dialect.
    # Validating under the wrong dialect silently rejects valid queries.
    policy = Policy(allowed_tables={"events"}, dialect="bigquery")
    assert check("SELECT * FROM `events` LIMIT 10", policy).ok


def test_enforce_returns_the_query_without_its_semicolon():
    assert enforce("SELECT id FROM users LIMIT 1;", POLICY) == "SELECT id FROM users LIMIT 1"


def test_enforce_raises_with_the_violations_attached():
    with pytest.raises(GuardError) as excinfo:
        enforce("DROP TABLE users", POLICY)
    assert excinfo.value.violations
    assert "not_read_only" in {v.code for v in excinfo.value.violations}


def test_result_is_falsy_when_rejected():
    assert not check("DROP TABLE users", POLICY)
    assert check("SELECT id FROM users LIMIT 1", POLICY)


def test_policy_helpers_do_not_mutate_the_original():
    base = Policy(allowed_tables={"users"})
    extended = base.with_tables("events")
    assert base.allowed_tables == {"users"}
    assert extended.allowed_tables == {"users", "events"}
