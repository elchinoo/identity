"""Row MACs: a database write alone (no data key) cannot forge identities, widen privileges, redirect codes or publish signing keys.
Every test plants or edits rows with plain SQL, as an attacker with write access but without the vault data key would."""
import json

import pytest
from apgkit import passwords
from conftest import BASE, CSRF, TEST_URL, authorize, code_from, exchange, login_sso, make_world, pkce
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from psycopg.types.json import Jsonb

from identity import cli, core, keys, rowmac, users

if not TEST_URL:
    pytest.skip("set TEST_DATABASE_URL to run database tests", allow_module_level=True)

ADA = "analytical engine 1843"


def sql(query, *params):
    with core.db.connect() as c:
        cur = c.execute(query, params)
        rows = cur.fetchall() if cur.description else []
        c.commit()
    return rows


def count(table):
    return rowmac.tampered.labels(table)._value.get()


def get_tokens(idp, w, scope="openid roles offline_access"):
    browser = login_sso(idp)
    pk = pkce()
    code, _ = code_from(authorize(browser, pk, scope=scope))
    return exchange(idp, code, pk[0], w["secret"], client_id="demo").json() | {"_pk": pk}


def decode(idp, token):
    return jwt.decode(token, KeySet.import_key_set(idp.get("/jwks.json").json())).claims


def grant(idp, uid, role, kind="user", subject=None):
    r = idp.post("/api/grants", headers=CSRF, json={"subject_type": kind, "subject": subject or uid, "client_id": "demo", "role": role})
    assert r.status_code in (200, 201), r.text


# ---- signing keys ----------------------------------------------------------------------------------------------------------
def test_a_planted_active_signing_key_is_neither_published_nor_used(idp):
    w = make_world(idp)
    good = sql("SELECT kid FROM signing_key WHERE status='active'")[0]["kid"]
    evil = RSAKey.generate_key(2048, {"kid": "evil", "use": "sig", "alg": "RS256"})
    before = count("signing_key")
    sql("INSERT INTO signing_key (kid, alg, private_enc, public_jwk, status, created_at) VALUES ('evil','RS256','x',%s,'active', now() + interval '1 day')",
        Jsonb(evil.as_dict(private=False)))
    keys.forget()
    assert [k["kid"] for k in idp.get("/jwks.json").json()["keys"]] == [good]
    tok = get_tokens(idp, w)
    assert jwt.decode(tok["access_token"], KeySet.import_key_set(idp.get("/jwks.json").json())).header["kid"] == good
    assert count("signing_key") > before


def test_an_edited_signing_key_row_drops_out_of_the_jwks(idp):
    make_world(idp)
    good = sql("SELECT kid FROM signing_key WHERE status='active'")[0]["kid"]
    evil = RSAKey.generate_key(2048, {"kid": good, "use": "sig", "alg": "RS256"})
    sql("UPDATE signing_key SET public_jwk=%s WHERE kid=%s", Jsonb(evil.as_dict(private=False)), good)     # swap in the attacker's public half
    assert idp.get("/jwks.json").json()["keys"] == []
    keys.forget()
    sql("UPDATE signing_key SET public_jwk=%s WHERE kid=%s", Jsonb({"kty": "x"}), good)
    with core.db.connect() as c:
        assert keys.ensure(c) != good                                     # no valid active key: a fresh one is made, never the edited one


def test_rotation_and_retirement_keep_valid_macs(idp):
    make_world(idp)
    with core.db.connect() as c:
        old = keys.ensure(c)
        new = keys.rotate(c)
    published = [k["kid"] for k in idp.get("/jwks.json").json()["keys"]]
    assert published == [new, old]
    sql("UPDATE signing_key SET retire_at = now() - interval '1 minute' WHERE kid=%s", old)        # an attacker moving the date is refused too
    assert [k["kid"] for k in idp.get("/jwks.json").json()["keys"]] == [new]
    with core.db.connect() as c:
        keys.rotate(c)
        rows = c.execute("SELECT * FROM signing_key").fetchall()
    assert all(rowmac.verify_row("signing_key", r) for r in rows if r["kid"] == new)


# ---- apps -----------------------------------------------------------------------------------------------------------------
def test_an_edited_app_is_refused(idp):
    make_world(idp)
    browser, pk = login_sso(idp), pkce()
    assert authorize(browser, pk).status_code == 302
    sql("UPDATE idp_app SET redirect_uris = redirect_uris || ARRAY['https://evil.example.org/cb'] WHERE client_id='demo'")
    r = authorize(login_sso(idp), pkce(), redirect="https://evil.example.org/cb")
    assert r.status_code != 302 or "evil.example.org" not in r.headers.get("location", "")
    assert authorize(login_sso(idp), pkce()).status_code != 302                  # the whole client is refused, not just the new URI


def test_an_edited_secret_hash_cannot_be_used(idp):
    from apgkit.ids import sha256
    make_world(idp)
    browser, pk = login_sso(idp), pkce()
    code, _ = code_from(authorize(browser, pk))
    sql("UPDATE idp_app SET secret_hash=%s WHERE client_id='demo'", sha256("attacker-chosen-secret"))
    r = exchange(idp, code, pk[0], "attacker-chosen-secret")
    assert r.status_code in (400, 401) and "access_token" not in r.json()


def test_edited_allowed_audiences_refuse_the_service_client(idp):
    w = make_world(idp)
    ok = idp.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "other.read"}, auth=("robot", w["robot_secret"]))
    assert ok.status_code == 200, ok.text
    sql("UPDATE idp_app SET allowed_audiences = allowed_audiences || ARRAY['demo','other','trustdesk'] WHERE client_id='robot'")
    bad = idp.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "trustdesk.admin"}, auth=("robot", w["robot_secret"]))
    assert bad.status_code in (400, 401) and "access_token" not in bad.json()


def test_planted_app_does_not_exist(idp):
    make_world(idp)
    sql("INSERT INTO idp_app (client_id, name, kind, redirect_uris) VALUES ('planted','P','public',ARRAY['https://evil.example.org/cb'])")
    r = authorize(login_sso(idp), pkce(), client_id="planted", redirect="https://evil.example.org/cb")
    assert r.status_code != 302
    assert "planted" not in [a["client_id"] for a in idp.get("/api/apps").json()]


# ---- roles ---------------------------------------------------------------------------------------------------------------
def test_a_planted_grant_does_not_reach_the_token(idp):
    w = make_world(idp)
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:viewer"]
    sql("INSERT INTO idp_role_grant (subject_type, subject_id, client_id, role) VALUES ('user',%s,'demo','admin')", w["uid"])
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:viewer"]
    grant(idp, w["uid"], "approver")                                                                # a genuine grant still works
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:approver", "demo:viewer"]


def test_a_planted_membership_does_not_reach_the_token(idp):
    w = make_world(idp)
    assert idp.post("/api/groups", headers=CSRF, json={"name": "ops", "description": ""}).status_code in (200, 201)
    grant(idp, None, "admin", kind="group", subject="ops")
    gid = sql("SELECT id FROM idp_group WHERE name='ops'")[0]["id"]
    sql("INSERT INTO idp_membership (user_id, group_id) VALUES (%s,%s)", w["uid"], gid)
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:viewer"]
    assert idp.post(f"/api/users/{w['uid']}/groups", headers=CSRF, json={"group": "ops"}).status_code in (200, 201)      # the real one does
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:admin", "demo:viewer"]


def test_edited_default_roles_are_refused(idp):
    w = make_world(idp)
    sql("UPDATE idp_app SET default_roles = ARRAY['admin'] WHERE client_id='demo'")
    with core.db.connect() as c:
        assert users.roles_for(c, w["uid"], "demo") == []                 # the app row no longer verifies: nothing is granted


def test_a_grant_whose_fields_were_edited_is_ignored(idp):
    w = make_world(idp)
    grant(idp, w["uid"], "approver")
    sql("UPDATE idp_role_grant SET role='admin' WHERE role='approver'")
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:viewer"]


# ---- users ---------------------------------------------------------------------------------------------------------------
def login(idp, username, password):
    return TestClient(idp.app, base_url=BASE).post("/login", json={"username": username, "password": password}, headers=CSRF)


def test_a_planted_user_cannot_log_in(idp):
    make_world(idp)
    sql("INSERT INTO idp_user (id, username, email, password_hash) VALUES ('usr_plantedplanted','mallory','m@example.org',%s)", passwords.hash_password("mallory password long"))
    assert login(idp, "mallory", "mallory password long").status_code == 401
    assert "mallory" not in [u["username"] for u in idp.get("/api/users").json()]


def test_an_edited_password_hash_or_status_cannot_log_in(idp):
    w = make_world(idp)
    assert login(idp, "ada", ADA).status_code == 200
    original = sql("SELECT password_hash FROM idp_user WHERE id=%s", w["uid"])[0]["password_hash"]
    sql("UPDATE idp_user SET password_hash=%s WHERE id=%s", passwords.hash_password("attacker new password"), w["uid"])
    assert login(idp, "ada", "attacker new password").status_code == 401
    assert login(idp, "ada", ADA).status_code == 401                       # even the real password: the row as a whole is untrusted
    sql("UPDATE idp_user SET password_hash=%s WHERE id=%s", original, w["uid"])
    assert idp.patch(f"/api/users/{w['uid']}", headers=CSRF, json={"status": "disabled"}).status_code == 200
    assert login(idp, "ada", ADA).status_code == 401
    sql("UPDATE idp_user SET status='active' WHERE id=%s", w["uid"])
    assert login(idp, "ada", ADA).status_code == 401


def test_genuine_admin_edits_keep_a_user_signed(idp):
    w = make_world(idp)
    assert idp.patch(f"/api/users/{w['uid']}", headers=CSRF, json={"email": "ada2@example.org"}).status_code == 200
    assert idp.put(f"/api/users/{w['uid']}/password", headers=CSRF, json={"password": "a brand new long password"}).status_code in (200, 204)
    assert login(idp, "ada", "a brand new long password").status_code == 200


# ---- codes and refresh tokens ----------------------------------------------------------------------------------------------
def test_a_planted_code_cannot_be_redeemed(idp):
    from apgkit.ids import sha256
    w = make_world(idp)
    verifier, challenge = pkce()
    sql("INSERT INTO oauth_code (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, auth_time, expires_at) "
        "VALUES (%s,'demo',%s,'https://demo.example.org/auth/callback','openid roles',%s,%s, now() + interval '1 minute')",
        sha256("planted-code"), w["uid"], challenge, 1)
    r = exchange(idp, "planted-code", verifier, w["secret"])
    assert r.status_code == 400 and "access_token" not in r.json()


def test_an_edited_code_is_refused(idp):
    w = make_world(idp)
    browser, pk = login_sso(idp), pkce()
    code, _ = code_from(authorize(browser, pk, scope="openid"))
    sql("UPDATE oauth_code SET scope='openid roles offline_access', redirect_uri='https://evil.example.org/cb'")
    r = exchange(idp, code, pk[0], w["secret"])
    assert r.status_code == 400 and "access_token" not in r.json()


def test_a_planted_refresh_token_cannot_be_used(idp):
    from apgkit.ids import sha256
    w = make_world(idp)
    sql("INSERT INTO oauth_refresh (token_hash, family_id, client_id, user_id, scope, auth_time, expires_at) "
        "VALUES (%s,'fam_x','demo',%s,'openid roles offline_access',1, now() + interval '1 day')", sha256("rt_planted"), w["uid"])
    r = idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "rt_planted"}, auth=("demo", w["secret"]))
    assert r.status_code == 400 and "access_token" not in r.json()


def test_an_edited_refresh_token_is_refused_and_a_genuine_one_rotates(idp):
    w = make_world(idp)
    tok = get_tokens(idp, w)
    ok = idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, auth=("demo", w["secret"]))
    assert ok.status_code == 200, ok.text
    sql("UPDATE oauth_refresh SET scope='openid roles offline_access demo.write', expires_at = now() + interval '5 years'")
    again = idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": ok.json()["refresh_token"]}, auth=("demo", w["secret"]))
    assert again.status_code == 400 and "access_token" not in again.json()


def test_undoing_a_revocation_by_edit_does_not_revive_a_token(idp):
    w = make_world(idp)
    tok = get_tokens(idp, w)
    assert idp.post("/oauth/revoke", data={"token": tok["refresh_token"]}, auth=("demo", w["secret"])).status_code == 200
    sql("UPDATE oauth_refresh SET revoked_at=NULL")
    r = idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, auth=("demo", w["secret"]))
    assert r.status_code == 400


# ---- federation ----------------------------------------------------------------------------------------------------------
def test_an_edited_federation_provider_is_ignored(idp):
    from identity import federation
    make_world(idp)
    assert idp.put("/api/federation/google", headers=CSRF, json={"client_id": "g", "client_secret": "s"}).status_code == 200
    with core.db.connect() as c:
        assert [p["provider"] for p in federation.list_providers(c)] == ["google"]
    sql("UPDATE federation_provider SET mode='open', allowed_domains=ARRAY['evil.example.org']")
    with core.db.connect() as c:
        assert federation.list_providers(c) == [] and federation.enabled(c) == []
        with pytest.raises(federation.FederationError):
            federation._config(c, "google")
    assert TestClient(idp.app, base_url=BASE).get("/login/google", follow_redirects=False).status_code != 302


def test_a_planted_federated_link_does_not_sign_anyone_in(idp):
    from identity import federation
    w = make_world(idp)
    assert idp.put("/api/federation/google", headers=CSRF, json={"client_id": "g", "client_secret": "s"}).status_code == 200
    sql("INSERT INTO idp_federated (provider, subject, user_id) VALUES ('google','attacker-sub',%s)", w["uid"])
    with core.db.connect() as c:
        cfg = federation._config(c, "google")
        with pytest.raises(federation.FederationError):                  # invite-only: the planted link counts for nothing, no e-mail match
            federation.resolve(c, cfg, "google", {"sub": "attacker-sub", "email": "nobody@example.net", "email_verified": True})


# ---- bookkeeping ---------------------------------------------------------------------------------------------------------
def test_tampering_is_counted_logged_and_audited_once(idp, caplog):
    make_world(idp)
    n = count("idp_user")
    sql("INSERT INTO idp_user (id, username, email) VALUES ('usr_audittestaudit','eve','e@example.org')")
    with caplog.at_level("WARNING", logger="identity.rowmac"):
        for _ in range(3):
            login(idp, "eve", "whatever")
    assert count("idp_user") >= n + 3
    assert sum("usr_audittestaudit" in m for m in caplog.messages) == 1 and all("e@example.org" not in m for m in caplog.messages)
    assert len(sql("SELECT 1 FROM idp_audit WHERE action='row_mac_invalid' AND target='idp_user:usr_audittestaudit'")) == 1


def test_a_locked_vault_fails_closed(idp):
    w = make_world(idp)
    with core.db.connect() as c:
        row = c.execute("SELECT * FROM idp_user WHERE id=%s", (w["uid"],)).fetchone()
    assert rowmac.verify_row("idp_user", row)
    core.vault.lock()
    assert not rowmac.verify_row("idp_user", row)


def test_adopt_signs_unsigned_rows_and_trusts_them(idp, capsys):
    w = make_world(idp)
    grant(idp, w["uid"], "approver")
    for t in rowmac.TABLES:
        sql(f"UPDATE {t} SET mac=NULL")                                    # a database from before row MACs
    assert login(idp, "ada", ADA).status_code == 401
    assert cli.main(["adopt-rowmacs"]) == 0
    out = capsys.readouterr().out
    assert "idp_user 1" in out and "idp_app 3" in out and "trusted the database" in out
    assert login(idp, "ada", ADA).status_code == 200
    assert decode(idp, get_tokens(idp, w)["access_token"])["roles"] == ["demo:approver", "demo:viewer"]
    assert len(idp.get("/jwks.json").json()["keys"]) == 1
    assert cli.main(["adopt-rowmacs"]) == 0 and "idp_user 0" in capsys.readouterr().out         # idempotent


def test_vault_key_rotation_keeps_everything_signed(idp):
    from identity import keys as k
    w = make_world(idp)
    tok = get_tokens(idp, w)
    with core.db.connect() as c:
        k.rotate_vault_key(c, "test", "correct horse battery staple")
    assert login(idp, "ada", ADA).status_code == 200
    assert idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, auth=("demo", w["secret"])).status_code == 200
    assert len(idp.get("/jwks.json").json()["keys"]) == 1
    assert json.dumps(idp.get("/api/users").json())
