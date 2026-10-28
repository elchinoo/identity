"""Database insights (EDB extensions, degrading) and read-only / AI hardening proven with a real read-only login role."""
import re

import psycopg
import pytest
from conftest import CSRF, TEST_URL, TestClient
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

LOGIN = "identity_ro_login"


def test_kit_is_at_least_0_3_0():
    import apgkit
    assert tuple(int(x) for x in apgkit.__version__.split(".")[:3]) >= (0, 3, 0)


@pytest.fixture
def ro(idp):
    """A login role that is a member of a1p_readonly, with what AgentPG's default privileges give it (SELECT on every public table)."""
    from identity import core, hardening
    with core.db.connect() as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='a1p_readonly') THEN CREATE ROLE a1p_readonly NOLOGIN; END IF; END $$")
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{LOGIN}') THEN CREATE ROLE {LOGIN} LOGIN; END IF; END $$")
        c.execute(f"GRANT a1p_readonly TO {LOGIN}")
        c.execute("GRANT USAGE ON SCHEMA public TO a1p_readonly")
        c.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO a1p_readonly")
        c.commit()
    idp.post("/api/users", headers=CSRF, json={"username": "ada", "email": "ada@example.org", "name": "Ada Lovelace", "password": "analytical engine 1843"})
    idp.post("/api/apps", headers=CSRF, json={"client_id": "demo", "name": "Demo", "kind": "web", "redirect_uris": ["https://demo.example.org/cb"], "roles": []})
    from identity import cli
    cli.run_migrations()                                   # the real startup path: the after-migrate hook hardens
    conn = psycopg.connect(make_conninfo(TEST_URL, user=LOGIN), row_factory=dict_row, autocommit=True)
    yield conn
    conn.close()
    assert hardening.ROLE == "a1p_readonly"


def test_read_only_login_cannot_read_the_signing_keys(idp, ro):
    """MOST SENSITIVE TABLE OF THE FLEET: encrypted private signing keys. A read-only database user (and an AI agent on AgentPG's restricted MCP) must not read it."""
    from identity import core
    with core.db.connect() as c:
        assert c.execute("SELECT count(*) AS n FROM signing_key").fetchone()["n"] >= 1          # the owner sees the key: the test is meaningful
    for q in ("SELECT * FROM signing_key", "SELECT private_enc FROM signing_key", "SELECT kid FROM signing_key"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            ro.execute(q)


def test_secret_tables_are_denied_and_masked_views_readable(idp, ro):
    from identity import hardening
    for t in hardening.DENIED_TABLES:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            ro.execute(f'SELECT * FROM "{t}"')
    for t in ("idp_user", "idp_federated", "idp_app"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            ro.execute(f"SELECT * FROM {t}")                  # base tables with personal data or hashes
    row = ro.execute("SELECT * FROM idp_user_masked WHERE username LIKE 'a%'").fetchone()
    assert row["username"] == "a***" and row["name"] == "A***" and row["email"] == "***@example.org"
    assert "password_hash" not in row
    app = ro.execute("SELECT * FROM idp_app_masked WHERE client_id='demo'").fetchone()
    assert "secret_hash" not in app and app["name"] == "Demo"
    with pytest.raises(psycopg.Error):
        ro.execute("UPDATE idp_user_masked SET status='disabled'")
    ro.execute("SELECT count(*) FROM idp_group")               # ordinary non-sensitive tables stay readable


def test_every_secret_looking_column_is_covered(idp, ro):
    """Guards new migrations: a hash/secret/ciphertext/key column must be in a denied table or absent from the masked view."""
    from identity import core, hardening
    pat = re.compile(r"hash|secret|_enc$|private|verifier|password|token")
    with core.db.connect() as c:
        cols = c.execute("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND table_name NOT LIKE '%\\_masked'").fetchall()
    uncovered = []
    for r in cols:
        t, col = r["table_name"], r["column_name"]
        if not pat.search(col) or t in hardening.DENIED_TABLES:
            continue
        view = hardening.MASKED_VIEWS.get(t)
        if t.endswith("_migrations") or (view and col not in view[1] and not ro.execute("SELECT has_table_privilege(%s, 'SELECT') AS ok", (t,)).fetchone()["ok"]):
            continue
        uncovered.append((t, col))
    assert not uncovered, f"secret-looking columns readable by a1p_readonly: {uncovered}"


def test_hardening_is_idempotent_and_quiet_without_the_role(idp, ro):
    from identity import core, hardening
    with core.db.connect() as c:
        a, b = hardening.apply(c), hardening.apply(c)
        assert a == b and all(a["masked"].values()) and all(a["denied"].values())
        assert hardening.apply(c, role="no_such_readonly_role") == {"role_exists": False, "masked": {}, "denied": {}}


def test_insights_route_needs_full_admin_and_degrades_on_plain_postgres(idp):
    anon = TestClient(idp.app, base_url="http://localhost")
    assert anon.get("/api/insights").status_code in (401, 403)
    read = idp.post("/api/tokens", headers=CSRF, json={"name": "r", "scope": "read"}).json()["token"]
    assert anon.get("/api/insights", headers={"Authorization": f"Bearer {read}"}).status_code == 403      # statement text is admin-only
    r = idp.get("/api/insights?order=mean&limit=5")
    assert r.status_code == 200
    d = r.json()
    assert set(d) == {"sources", "top_queries", "tuner", "advisor"}
    assert d["tuner"]["available"] is False and d["advisor"]["available"] is False       # no EDB extensions on the throwaway Postgres
    assert d["sources"]["edb_stat_monitor"]["available"] is False and d["sources"]["edb_stat_monitor"]["reason"]
    assert idp.get("/api/insights?order=bogus").status_code == 200                       # a bad order falls back instead of failing


def test_insights_metrics_are_exported(idp):
    from identity import core
    body, _ = core.metrics.render()
    assert b'db_insights_available{app="identity"}' in body
    assert b"db_insights_tuner_recommendations" not in body             # absent when edb_pg_tuner is unavailable


def test_console_has_a_database_tab_mounting_the_kit_insights():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src" / "identity" / "static" / "admin.js").read_text()
    assert 'import { initInsights } from "/kit/insights.js"' in js and 'insights: "Database"' in js and "initInsights($(\"view\"), api)" in js
