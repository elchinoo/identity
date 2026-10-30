"""Emergency signing-key rotation (hard revoke), the narrow deploy credential, a rotatable admin key, a configurable refresh lifetime."""
import pytest
from apgkit.auth import TokenError, TokenVerifier
from conftest import BASE, CSRF, authorize, code_from, exchange, http_for, login_sso, make_world, pkce
from fastapi.testclient import TestClient


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def anon(idp):
    return TestClient(idp.app, base_url=BASE)


def issue(idp, w, scope="openid offline_access"):
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope=scope))
    return exchange(idp, code, pk[0], w["secret"]).json()


def refresh(idp, w, rt):
    return idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": rt}, auth=("demo", w["secret"]))


def kids(idp):
    return [k["kid"] for k in idp.get("/jwks.json").json()["keys"]]


def test_emergency_rotation_removes_every_old_key_and_refuses_their_tokens(idp, monkeypatch):
    w = make_world(idp)
    graceful_old = kids(idp)[0]
    assert idp.post("/api/keys/rotate", headers=CSRF).status_code == 200      # the default path keeps the old key published
    assert len(kids(idp)) == 2
    tok = issue(idp, w)
    old_access = tok["access_token"]
    cached = TokenVerifier(BASE, "demo", http=http_for(idp), ttl=300)
    assert cached.verify(old_access)["sub"] == w["uid"]

    r = idp.post("/api/keys/emergency-rotate", headers=CSRF, json={"confirm": True, "reason": "test"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert graceful_old in out["removed_keys"] and len(out["removed_keys"]) == 2
    assert kids(idp) == [out["kid"]]                                              # the JWKS lists only the new key, at once
    assert old_access.split(".")[0] != out["kid"]
    with pytest.raises(TokenError):
        TokenVerifier(BASE, "demo", http=http_for(idp)).verify(old_access)        # a verifier with a fresh cache refuses it
    assert anon(idp).get("/oauth/userinfo", headers=bearer(old_access)).status_code == 401   # so does Identity itself

    # a verifier that cached the old JWKS keeps accepting until its TTL passes, then refuses
    clock = [1000.0]
    monkeypatch.setattr("apgkit.auth.oidc.time.monotonic", lambda: clock[0])
    stale = TokenVerifier(BASE, "demo", http=http_for(idp), ttl=300)
    clock[0] += 1
    new_tok = issue(idp, w)["access_token"]
    assert stale.verify(new_tok)["sub"] == w["uid"]
    assert new_tok.split(".")[0] != old_access.split(".")[0]
    assert TokenVerifier(BASE, "demo", http=http_for(idp)).verify(new_tok)["sub"] == w["uid"]


def test_emergency_rotation_revokes_refresh_tokens_and_sso_sessions_and_is_audited(idp):
    w = make_world(idp)
    browser = login_sso(idp)
    pk = pkce()
    code, _ = code_from(authorize(browser, pk, scope="openid offline_access"))
    rt = exchange(idp, code, pk[0], w["secret"]).json()["refresh_token"]
    assert authorize(browser, pkce()).status_code == 302 and "code=" in authorize(browser, pkce()).headers["location"]   # SSO session is live
    r = idp.post("/api/keys/emergency-rotate", headers=CSRF, json={"confirm": True, "reason": "drill"})
    assert r.status_code == 200 and r.json()["refresh_tokens_revoked"] >= 1 and r.json()["sso_sessions_ended"] >= 1
    assert refresh(idp, w, rt).status_code == 400                                # the refresh token no longer works
    assert authorize(browser, pkce()).headers["location"].startswith("/login")   # the browser has to sign in again
    assert idp.get("/api/overview").json()["live_refresh_tokens"] == 0           # the admin session itself survives
    row = idp.get("/api/audit").json()[0]
    assert row["action"] == "signing_key_emergency_rotated" and row["target"] == r.json()["kid"]
    assert row["detail"]["reason"] == "drill" and row["detail"]["removed_keys"]
    # signing works under the new key
    assert issue(idp, w)["access_token"]


def test_emergency_rotation_needs_confirmation_and_full_admin(idp):
    make_world(idp)
    before = kids(idp)
    assert idp.post("/api/keys/emergency-rotate", headers=CSRF, json={}).status_code == 422
    assert idp.post("/api/keys/emergency-rotate", headers=CSRF, json={"confirm": False}).status_code == 422
    assert kids(idp) == before                                                    # nothing happened
    read = idp.post("/api/tokens", headers=CSRF, json={"name": "look", "scope": "read"}).json()["token"]
    assert anon(idp).post("/api/keys/emergency-rotate", headers=bearer(read), json={"confirm": True}).status_code == 403
    assert anon(idp).post("/api/keys/emergency-rotate", headers=CSRF, json={"confirm": True}).status_code == 401
    assert kids(idp) == before


def test_cli_emergency_rotation(idp, capsys):
    from identity import cli, core
    make_world(idp)
    old = kids(idp)
    assert cli.main(["rotate-keys", "--emergency"]) == 2                          # refuses without --yes
    assert kids(idp) == old
    assert cli.main(["rotate-keys", "--emergency", "--yes", "--reason", "drill"]) == 0
    new = kids(idp)
    assert len(new) == 1 and new != old
    assert "emergency rotation done" in capsys.readouterr().out
    assert idp.get("/api/audit").json()[0]["action"] == "signing_key_emergency_rotated"
    assert cli.main(["rotate-keys"]) == 0                                         # graceful stays the default: old key still published
    assert len(kids(idp)) == 2 and new[0] in kids(idp)
    assert idp.get("/api/audit").json()[0]["action"] == "signing_key_rotated"
    core.vault.lock()
    assert cli.main(["rotate-keys", "--emergency", "--yes"]) == 1                 # a locked vault cannot make a key
    assert len(kids(idp)) == 2


def test_deploy_key_can_register_and_grant_but_nothing_sensitive(idp, monkeypatch):
    w = make_world(idp)
    monkeypatch.setenv("IDENTITY_DEPLOY_KEY", "deploy-key-for-tests-0123456789")
    a, H = anon(idp), bearer("deploy-key-for-tests-0123456789")
    assert a.get("/api/apps", headers=H).status_code == 200
    r = a.post("/api/apps", headers=H, json={"client_id": "newapp", "name": "New", "kind": "web", "redirect_uris": ["https://n.example.org/cb"], "roles": [{"name": "admin"}]})
    assert r.status_code == 201
    assert a.patch("/api/apps/newapp", headers=H, json={"url": "https://n.example.org"}).status_code == 200
    assert a.post("/api/groups", headers=H, json={"name": "ops"}).status_code == 201
    assert a.post("/api/grants", headers=H, json={"subject_type": "group", "subject": "ops", "client_id": "newapp", "role": "admin"}).status_code == 201
    # what it must not do
    assert a.post("/api/apps/newapp/secret", headers=H).status_code == 403
    assert a.delete("/api/apps/newapp", headers=H).status_code == 403
    assert a.post("/api/users", headers=H, json={"username": "eve", "email": "eve@example.org"}).status_code == 403
    assert a.put(f"/api/users/{w['uid']}/password", headers=H, json={"password": "another long passphrase"}).status_code == 403
    assert a.delete("/api/groups/ops", headers=H).status_code == 403
    assert a.post("/api/keys/rotate", headers=H).status_code == 403
    assert a.post("/api/keys/emergency-rotate", headers=H, json={"confirm": True}).status_code == 403
    assert a.put("/api/federation/github", headers=H, json={"client_id": "x"}).status_code == 403
    assert a.post("/api/tokens", headers=H, json={"name": "x", "scope": "full"}).status_code == 403
    assert a.get("/api/insights", headers=H).status_code == 403
    assert a.get("/api/apps", headers=bearer("wrong-key")).status_code == 401


def test_admin_api_key_can_be_rotated_without_a_lockout(idp, monkeypatch):
    make_world(idp)
    a = anon(idp)
    monkeypatch.setenv("IDENTITY_API_KEY", "old-admin-key-for-tests-0123456789")
    assert a.get("/api/apps", headers=bearer("old-admin-key-for-tests-0123456789")).status_code == 200
    monkeypatch.setenv("IDENTITY_API_KEY_NEXT", "new-admin-key-for-tests-0123456789")        # both work during the changeover
    assert a.post("/api/groups", headers=bearer("new-admin-key-for-tests-0123456789"), json={"name": "g1"}).status_code == 201
    assert a.get("/api/apps", headers=bearer("old-admin-key-for-tests-0123456789")).status_code == 200
    monkeypatch.setenv("IDENTITY_API_KEY", "new-admin-key-for-tests-0123456789")             # promote NEXT, drop it
    monkeypatch.delenv("IDENTITY_API_KEY_NEXT")
    assert a.get("/api/apps", headers=bearer("new-admin-key-for-tests-0123456789")).status_code == 200
    assert a.get("/api/apps", headers=bearer("old-admin-key-for-tests-0123456789")).status_code == 401
    assert a.get("/api/apps", headers=bearer("")).status_code in (401, 403)


def test_admin_key_next_can_come_from_a_file(idp, monkeypatch, tmp_path):
    make_world(idp)
    f = tmp_path / "next"
    f.write_text("file-admin-key-for-tests-0123456789\n")
    monkeypatch.setenv("IDENTITY_API_KEY_NEXT_FILE", str(f))
    assert anon(idp).get("/api/apps", headers=bearer("file-admin-key-for-tests-0123456789")).status_code == 200


def test_refresh_token_lifetime_is_configurable_and_the_default_is_unchanged(idp, monkeypatch):
    from identity import core, oauth
    w = make_world(idp)

    def lifetime_days():
        issue(idp, w)
        with core.db.connect() as conn:
            row = conn.execute("SELECT extract(epoch FROM (expires_at - created_at)) AS s FROM oauth_refresh ORDER BY id DESC LIMIT 1").fetchone()
        return round(float(row["s"]) / 86400)
    assert oauth.refresh_ttl() == 30 * 86400 and lifetime_days() == 30
    monkeypatch.setenv("IDENTITY_REFRESH_TTL_DAYS", "7")
    assert oauth.refresh_ttl() == 7 * 86400 and lifetime_days() == 7
    for bad in ("0", "0.5", "-3", "9999", "abc", ""):
        monkeypatch.setenv("IDENTITY_REFRESH_TTL_DAYS", bad)
        assert oauth.refresh_ttl() == 30 * 86400, bad
