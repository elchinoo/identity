"""The operator console API, its boundaries, and the login surface."""
from conftest import BASE, CSRF, PASSWORD, login_sso, make_world
from fastapi.testclient import TestClient


def anon(idp):
    return TestClient(idp.app, base_url=BASE)


def test_admin_api_needs_an_admin_session_and_the_csrf_header(idp):
    make_world(idp)
    a = anon(idp)
    for path in ("/api/users", "/api/apps", "/api/groups", "/api/grants", "/api/keys", "/api/audit", "/api/overview", "/api/federation", "/api/tokens"):
        assert a.get(path).status_code == 401, path
    assert a.post("/api/users", json={}, headers=CSRF).status_code == 401
    assert idp.post("/api/users", json={"username": "bob", "email": "bob@example.org"}).status_code == 403          # cookie write without the CSRF header
    assert idp.post("/api/users", json={"username": "bob", "email": "bob@example.org"}, headers=CSRF).status_code == 201


def test_a_signed_in_person_is_not_an_administrator(idp):
    make_world(idp)
    person = login_sso(idp)                       # holds the SSO cookie, which the admin API never reads
    assert person.get("/api/users").status_code == 401
    assert person.get("/api/overview").status_code == 401
    stolen = TestClient(idp.app, base_url=BASE)
    stolen.cookies.set("idp_admin", person.cookies.get("idp_sso"))                  # even presenting the SSO value as the admin cookie
    assert stolen.get("/api/users").status_code in (401, 403)
    assert person.get("/api/my-apps").status_code == 200


def test_operator_tokens_respect_their_scope(idp):
    make_world(idp)
    full = idp.post("/api/tokens", headers=CSRF, json={"name": "ci", "scope": "full"}).json()["token"]
    read = idp.post("/api/tokens", headers=CSRF, json={"name": "look", "scope": "read"}).json()["token"]
    metrics = idp.post("/api/tokens", headers=CSRF, json={"name": "scrape", "scope": "metrics"}).json()["token"]
    a = anon(idp)
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    assert a.get("/api/users", headers=H(read)).status_code == 200
    assert a.post("/api/users", json={"username": "x1", "email": "x1@example.org"}, headers=H(read)).status_code == 403
    assert a.post("/api/users", json={"username": "x1", "email": "x1@example.org"}, headers=H(full)).status_code == 201
    assert a.get("/metrics", headers=H(metrics)).status_code == 200 and a.get("/metrics", headers=H(read)).status_code == 403
    assert a.get("/api/users", headers=H(metrics)).status_code == 403


def test_app_registration_rules_and_secret_handling(idp):
    h = CSRF
    ok = {"client_id": "good", "name": "Good", "kind": "web", "redirect_uris": ["https://good.example.org/cb"], "roles": [{"name": "admin"}]}
    r = idp.post("/api/apps", headers=h, json=ok)
    assert r.status_code == 201 and r.json()["client_secret"].startswith("cs_")
    assert "client_secret" not in idp.get("/api/apps/good").text and "secret_hash" not in idp.get("/api/apps/good").text     # only ever shown once
    from identity import core
    with core.db.connect() as c:
        stored = c.execute("SELECT secret_hash FROM idp_app WHERE client_id='good'").fetchone()["secret_hash"]
    assert r.json()["client_secret"] not in stored and len(stored) == 64
    bad = [({"client_id": "Bad Name"}, "client id"), ({"redirect_uris": ["http://evil.example.org/cb"]}, "https"), ({"redirect_uris": ["https://x.org/*"]}, "redirect"),
           ({"redirect_uris": ["https://x.org/cb#frag"]}, "redirect"), ({"redirect_uris": []}, "redirect URI"), ({"default_roles": ["ghost"]}, "default_roles"),
           ({"roles": [{"name": "Bad Role"}]}, "roles"), ({"allowed_audiences": ["Not A Client"]}, "allowed_audiences")]
    for patch, _ in bad:
        spec = {**ok, "client_id": "other-app", **patch}
        assert idp.post("/api/apps", headers=h, json=spec).status_code == 422, patch
    assert idp.post("/api/apps", headers=h, json=ok).status_code == 422                              # duplicate client id
    assert idp.post("/api/apps", headers=h, json={**ok, "client_id": "loop", "redirect_uris": ["http://localhost:8080/cb"]}).status_code == 201
    new = idp.post("/api/apps/good/secret", headers=h).json()["client_secret"]
    assert new != r.json()["client_secret"] and idp.post("/api/apps/good/secret", headers=h).status_code == 200
    pub = idp.post("/api/apps", headers=h, json={"client_id": "pubapp", "name": "P", "kind": "public", "redirect_uris": ["https://p.example.org/cb"]})
    assert idp.post("/api/apps/pubapp/secret", headers=h).status_code == 422 and pub.status_code == 201


def test_removing_a_role_from_an_app_removes_its_grants(idp):
    w = make_world(idp)
    idp.post("/api/grants", headers=CSRF, json={"subject_type": "user", "subject": w["uid"], "client_id": "demo", "role": "approver"})
    assert len(idp.get("/api/grants", params={"client_id": "demo"}).json()) == 1
    assert idp.patch("/api/apps/demo", headers=CSRF, json={"roles": [{"name": "admin"}, {"name": "viewer"}]}).status_code == 200
    assert idp.get("/api/grants", params={"client_id": "demo"}).json() == []


def test_user_rules_and_login_hardening(idp):
    h = CSRF
    for bad in ({"username": "A", "email": "a@example.org"}, {"username": "ok", "email": "not-an-email"}, {"username": "ok2", "email": "o@example.org", "password": "short"}):
        assert idp.post("/api/users", headers=h, json=bad).status_code == 422, bad
    assert idp.post("/api/users", headers=h, json={"username": "dup", "email": "d@example.org"}).status_code == 201
    assert idp.post("/api/users", headers=h, json={"username": "dup2", "email": "D@EXAMPLE.org"}).status_code == 422          # e-mail unique, case-insensitively
    a = anon(idp)
    codes = [a.post("/login", json={"username": "nobody", "password": "wrong wrong wrong"}, headers=h).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    audit = idp.get("/api/audit").json()
    assert any(r["action"] == "login_failed" for r in audit) and any(r["action"] == "user_created" for r in audit)


def test_login_returns_only_local_next_paths(idp):
    make_world(idp)
    for nxt, expect in (("/apps", "/apps"), ("https://evil.example", "/"), ("//evil.example", "/"), (None, "/")):
        r = anon(idp).post("/login", json={"username": "ada@example.org", "password": "analytical engine 1843", "next": nxt}, headers=CSRF)
        assert r.status_code == 200 and r.json()["next"] == expect


def test_launcher_lists_only_apps_the_person_has_a_role_in(idp):
    w = make_world(idp)                              # demo has a default role (viewer); other has none
    data = login_sso(idp).get("/api/my-apps").json()
    assert [a["client_id"] for a in data["apps"]] == ["demo"] and data["apps"][0]["roles"] == ["viewer"]
    idp.post("/api/grants", headers=CSRF, json={"subject_type": "user", "subject": w["uid"], "client_id": "other", "role": "admin"})
    idp.patch("/api/apps/other", headers=CSRF, json={"url": "https://other.example.org"})
    assert {a["client_id"] for a in login_sso(idp).get("/api/my-apps").json()["apps"]} == {"demo", "other"}
    assert anon(idp).get("/api/my-apps").status_code == 401


def test_password_reset_ends_refresh_tokens_and_admin_password_change_signs_out(idp):
    w = make_world(idp)
    assert idp.put(f"/api/users/{w['uid']}/password", headers=CSRF, json={"password": "short"}).status_code == 422
    assert idp.put(f"/api/users/{w['uid']}/password", headers=CSRF, json={"password": "a brand new long password"}).status_code == 200
    assert anon(idp).post("/login", json={"username": "ada", "password": "analytical engine 1843"}, headers=CSRF).status_code == 401
    assert anon(idp).post("/login", json={"username": "ada", "password": "a brand new long password"}, headers=CSRF).status_code == 200
    r = idp.post("/api/admin-password", headers=CSRF, json={"current": PASSWORD, "new": "another long admin password"})
    assert r.status_code == 200 and idp.get("/api/users").status_code == 401


def test_a_locked_vault_means_no_tokens_and_not_ready(idp):
    from conftest import authorize, code_from, exchange, pkce

    from identity import core, keys
    w = make_world(idp)
    browser = login_sso(idp)
    pk = pkce()
    code, _ = code_from(authorize(browser, pk))
    core.vault.lock()
    keys.forget()                                                  # as after a restart without IDENTITY_ENCRYPTION_KEY
    ready = anon(idp).get("/readyz")
    assert ready.status_code == 503 and ready.json()["status"] == "locked"
    r = exchange(idp, code, pk[0], w["secret"])
    assert r.status_code == 503 and r.json()["error"] == "temporarily_unavailable" and r.headers["retry-after"] == "30"
    assert idp.get("/jwks.json").json()["keys"]                    # verifying existing tokens still works while locked
