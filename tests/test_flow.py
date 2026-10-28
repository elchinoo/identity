"""The OAuth 2.0 / OpenID Connect flows end to end, verified with the kit's own TokenVerifier."""
import time

import pytest
from apgkit.auth import AppAuth, TokenError, TokenVerifier
from apgkit.auth.oidc import discover, principal_from_claims
from conftest import BASE, CSRF, authorize, code_from, exchange, http_for, login_sso, make_world, pkce
from fastapi.testclient import TestClient

APP = AppAuth("demo", "demo", role_permissions={"admin": frozenset({"*"}), "viewer": frozenset({"things:read"}), "approver": frozenset({"things:decide"})},
              scope_permissions={"demo.write": frozenset({"things:write"})})


def verifier(idp, audience="demo"):
    return TokenVerifier(BASE, audience, http=http_for(idp))


def grant_role(idp, uid, role, client="demo"):
    r = idp.post("/api/grants", headers=CSRF, json={"subject_type": "user", "subject": uid, "client_id": client, "role": role})
    assert r.status_code == 201, r.text


def test_discovery_and_jwks(idp):
    doc = discover(BASE, http_for(idp))
    assert doc["issuer"] == BASE and doc["code_challenge_methods_supported"] == ["S256"] and "client_credentials" in doc["grant_types_supported"]
    keys = idp.get("/jwks.json").json()["keys"]
    assert len(keys) == 1 and keys[0]["kty"] == "RSA" and "d" not in keys[0] and keys[0]["kid"]       # the private part is never published


def test_authorization_code_flow_with_pkce(idp):
    w = make_world(idp)
    grant_role(idp, w["uid"], "approver")
    browser = login_sso(idp)
    pk = pkce()
    code, q = code_from(authorize(browser, pk, scope="openid profile email roles offline_access"))
    assert q["state"] == ["st"]
    r = exchange(idp, code, pk[0], w["secret"])
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["token_type"].lower() == "bearer" and tok["expires_in"] == 600 and tok["refresh_token"].startswith("rt_")
    claims = verifier(idp).verify(tok["access_token"])
    assert claims["sub"] == w["uid"] and claims["aud"] == "demo" and claims["sub_type"] == "user" and claims["client_id"] == "demo"
    assert claims["roles"] == ["demo:approver", "demo:viewer"]                       # a direct grant plus the app's default role
    assert claims["name"] == "Ada Lovelace" and claims["email"] == "ada@example.org"
    idc = verifier(idp).verify(tok["id_token"])
    assert idc["nonce"] == "n1" and idc["aud"] in ("demo", ["demo"]) and idc["roles"] == claims["roles"] and "auth_time" in idc
    p = principal_from_claims(APP, claims)
    assert p.can("things:decide") and p.can("things:read") and not p.can("things:write")


def test_roles_in_a_token_belong_to_the_audience_app_only(idp):
    w = make_world(idp)
    grant_role(idp, w["uid"], "admin", "other")                                         # admin of ANOTHER app
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk))
    claims = verifier(idp).verify(exchange(idp, code, pk[0], w["secret"]).json()["access_token"])
    assert claims["roles"] == ["demo:viewer"]                                           # the other app's admin role does not travel


def test_group_grants_reach_members(idp):
    w = make_world(idp)
    assert idp.post("/api/groups", headers=CSRF, json={"name": "approvers"}).status_code == 201
    assert idp.post(f"/api/users/{w['uid']}/groups", headers=CSRF, json={"group": "approvers"}).status_code == 200
    assert idp.post("/api/grants", headers=CSRF, json={"subject_type": "group", "subject": "approvers", "client_id": "demo", "role": "approver"}).status_code == 201
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk))
    claims = verifier(idp).verify(exchange(idp, code, pk[0], w["secret"]).json()["access_token"])
    assert "demo:approver" in claims["roles"]
    assert idp.post("/api/grants", headers=CSRF, json={"subject_type": "user", "subject": w["uid"], "client_id": "demo", "role": "nonsense"}).status_code == 422


def test_no_refresh_token_without_offline_access(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk))
    assert "refresh_token" not in exchange(idp, code, pk[0], w["secret"]).json()


def test_unauthenticated_authorize_goes_to_login_and_back(idp):
    make_world(idp)
    stranger = TestClient(idp.app, base_url=BASE)
    r = authorize(stranger, pkce())
    assert r.status_code == 302 and r.headers["location"].startswith("/login?next=%2Foauth%2Fauthorize")
    assert authorize(stranger, pkce(), prompt="none").status_code == 302
    assert "error=login_required" in authorize(stranger, pkce(), prompt="none").headers["location"]


def test_pkce_is_mandatory_for_every_client_and_s256_only(idp):
    make_world(idp)
    browser = login_sso(idp)
    base = {"response_type": "code", "client_id": "demo", "redirect_uri": "https://demo.example.org/auth/callback", "scope": "openid", "state": "s"}
    no_pkce = browser.get("/oauth/authorize", params=base, follow_redirects=False)       # a confidential client, but PKCE is still required
    assert no_pkce.status_code == 302 and "error=invalid_request" in no_pkce.headers["location"] and "code=" not in no_pkce.headers["location"]
    plain = browser.get("/oauth/authorize", params={**base, "code_challenge": "a" * 50, "code_challenge_method": "plain"}, follow_redirects=False)
    assert "error=invalid_request" in plain.headers["location"] and "code=" not in plain.headers["location"]
    nomethod = browser.get("/oauth/authorize", params={**base, "code_challenge": "a" * 50}, follow_redirects=False)
    assert "error=invalid_request" in nomethod.headers["location"]


def test_wrong_verifier_replay_and_redirect_binding(idp):
    w = make_world(idp)
    browser = login_sso(idp)
    pk = pkce()
    code, _ = code_from(authorize(browser, pk))
    assert exchange(idp, code, "x" * 50, w["secret"]).status_code == 400              # a wrong verifier...
    assert exchange(idp, code, pk[0], w["secret"]).status_code == 400                 # ...burns the code: even the right one fails now
    no_verifier = exchange(idp, code_from(authorize(browser, pk))[0], "", w["secret"])
    assert no_verifier.status_code == 400
    code2, _ = code_from(authorize(browser, pk))
    assert exchange(idp, code2, pk[0], w["secret"]).status_code == 200
    assert exchange(idp, code2, pk[0], w["secret"]).status_code == 400               # a code works once
    code3, _ = code_from(authorize(browser, pk))
    assert exchange(idp, code3, pk[0], w["secret"], redirect="https://demo.example.org/auth/callback2").status_code == 400
    assert exchange(idp, code3, pk[0], "cs_wrongsecret").status_code == 401           # wrong client secret
    assert exchange(idp, "not-a-code", pk[0], w["secret"]).status_code == 400


def test_a_code_belongs_to_the_client_that_asked_for_it(idp):
    make_world(idp)
    browser = login_sso(idp)
    pk = pkce()
    code, _ = code_from(authorize(browser, pk))
    other = idp.post("/api/apps/other/secret", headers=CSRF).json()["client_secret"]
    assert exchange(idp, code, pk[0], other, client_id="other", redirect="https://other.example.org/cb").status_code == 400


def test_redirect_uris_match_exactly_and_bad_clients_never_redirect(idp):
    make_world(idp)
    browser = login_sso(idp)
    for uri in ("https://demo.example.org/auth/callback/", "https://demo.example.org/auth/callbackx", "https://demo.example.org.evil.example/auth/callback",
                "https://demo.example.org/auth/callback?x=1", "http://demo.example.org/auth/callback"):
        r = authorize(browser, pkce(), redirect=uri)
        assert r.status_code == 400 and "location" not in r.headers, uri                     # an error page, never a redirect to an unregistered URI
    r = authorize(browser, pkce(), client_id="ghost")
    assert r.status_code == 400 and "location" not in r.headers


def test_scopes_a_client_may_not_request_are_refused(idp):
    make_world(idp)
    r = authorize(login_sso(idp), pkce(), scope="openid demo.write")                       # demo may request demo.write; fine
    assert r.status_code == 302 and "code=" in r.headers["location"]
    r = authorize(login_sso(idp), pkce(), scope="openid admin.everything")
    assert "error=invalid_scope" in r.headers["location"]


def test_refresh_rotation_and_reuse_detection(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope="openid offline_access"))
    first = exchange(idp, code, pk[0], w["secret"]).json()["refresh_token"]
    def refresh(token):
        return idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": token}, auth=("demo", w["secret"]))
    second = refresh(first)
    assert second.status_code == 200 and second.json()["refresh_token"] != first
    assert verifier(idp).verify(second.json()["access_token"])["sub"] == w["uid"]
    assert refresh(first).status_code == 400                                                # the old token again: theft assumed...
    assert refresh(second.json()["refresh_token"]).status_code == 400                       # ...so the whole family is dead
    assert refresh("rt_garbage").status_code == 400


def test_revocation_and_introspection(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope="openid offline_access"))
    rt = exchange(idp, code, pk[0], w["secret"]).json()["refresh_token"]
    info = idp.post("/oauth/introspect", data={"token": rt}, auth=("demo", w["secret"])).json()
    assert info["active"] is True and info["client_id"] == "demo"
    assert idp.post("/oauth/introspect", data={"token": rt}, auth=("other", idp.post("/api/apps/other/secret", headers=CSRF).json()["client_secret"])).json().get("active") is not True
    assert idp.post("/oauth/revoke", data={"token": rt}, auth=("demo", w["secret"])).status_code == 200
    assert idp.post("/oauth/introspect", data={"token": rt}, auth=("demo", w["secret"])).json()["active"] is False
    assert idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": rt}, auth=("demo", w["secret"])).status_code == 400


def test_disabled_user_and_disabled_app(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope="openid offline_access"))
    rt = exchange(idp, code, pk[0], w["secret"]).json()["refresh_token"]
    assert idp.patch(f"/api/users/{w['uid']}", headers=CSRF, json={"status": "disabled"}).status_code == 200
    assert idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": rt}, auth=("demo", w["secret"])).status_code == 400
    assert TestClient(idp.app, base_url=BASE).post("/login", json={"username": "ada", "password": "analytical engine 1843"}, headers=CSRF).status_code == 401
    idp.patch(f"/api/users/{w['uid']}", headers=CSRF, json={"status": "active"})
    idp.patch("/api/apps/demo", headers=CSRF, json={"status": "disabled"})
    assert authorize(login_sso(idp), pkce()).status_code == 400


def test_client_credentials_for_services(idp):
    w = make_world(idp)
    def token(scope, secret=None, client="robot", **kw):
        return idp.post("/oauth/token", data={"grant_type": "client_credentials", "scope": scope, **kw}, auth=(client, secret or w["robot_secret"]))
    r = token("demo.write")
    assert r.status_code == 200, r.text
    claims = verifier(idp, "demo").verify(r.json()["access_token"])
    assert claims["sub"] == "robot" and claims["sub_type"] == "service" and claims["scope"] == "demo.write" and "refresh_token" not in r.json()
    assert principal_from_claims(APP, claims).can("things:write")
    assert token("other.read").status_code == 200                                      # another app it may call
    assert token("demo.write other.read").status_code == 400                           # one audience per token
    assert token("demo.admin").status_code == 400                                      # a scope it was never allowed
    assert token("demo.write", secret="cs_wrong").status_code == 401
    ok = idp.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "demo.write"}, auth=("demo", w["secret"]))
    assert ok.status_code == 400                                                       # a user-facing app cannot use client credentials
    with pytest.raises(TokenError):
        verifier(idp, "other").verify(r.json()["access_token"])                        # the token is for `demo`, not `other`


def test_public_client_with_pkce_and_no_secret(idp):
    w = make_world(idp)
    r = idp.post("/api/apps", headers=CSRF, json={"client_id": "spa", "name": "SPA", "kind": "public", "redirect_uris": ["http://localhost:3000/cb"]})
    assert r.status_code == 201 and r.json()["client_secret"] is None
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, client_id="spa", redirect="http://localhost:3000/cb"))
    ok = exchange(idp, code, pk[0], None, client_id="spa", redirect="http://localhost:3000/cb")
    assert ok.status_code == 200 and verifier(idp, "spa").verify(ok.json()["access_token"])["sub"] == w["uid"]
    code, _ = code_from(authorize(login_sso(idp), pk, client_id="spa", redirect="http://localhost:3000/cb"))
    assert exchange(idp, code, "y" * 50, None, client_id="spa", redirect="http://localhost:3000/cb").status_code == 400


def test_userinfo_and_logout(idp):
    w = make_world(idp)
    pk = pkce()
    browser = login_sso(idp)
    code, _ = code_from(authorize(browser, pk))
    tok = exchange(idp, code, pk[0], w["secret"]).json()
    ui = idp.get("/oauth/userinfo", headers={"Authorization": f"Bearer {tok['access_token']}"})
    assert ui.status_code == 200 and ui.json()["sub"] == w["uid"] and ui.json()["email"] == "ada@example.org"
    assert idp.get("/oauth/userinfo", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert idp.get("/oauth/userinfo").status_code == 401
    out = browser.get("/oauth/logout", params={"client_id": "demo", "post_logout_redirect_uri": "https://demo.example.org/", "state": "bye"}, follow_redirects=False)
    assert out.status_code == 302 and out.headers["location"].startswith("https://demo.example.org/?state=bye")
    assert authorize(browser, pkce()).headers["location"].startswith("/login")            # the SSO session is gone
    again = login_sso(idp).get("/oauth/logout", params={"client_id": "demo", "post_logout_redirect_uri": "https://evil.example/"}, follow_redirects=False)
    assert again.headers["location"].startswith("/login")                                  # an unregistered return URI is ignored


def test_signing_key_rotation_keeps_old_tokens_valid(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk))
    old = exchange(idp, code, pk[0], w["secret"]).json()["access_token"]
    assert idp.post("/api/keys/rotate", headers=CSRF).status_code == 200
    jwks = idp.get("/jwks.json").json()["keys"]
    assert len(jwks) == 2
    v = verifier(idp)
    assert v.verify(old)["sub"] == w["uid"]
    pk2 = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk2))
    new = exchange(idp, code, pk2[0], w["secret"]).json()["access_token"]
    assert v.verify(new)["sub"] == w["uid"] and old.split(".")[0] != new.split(".")[0]      # signed with a different key id
    assert time.time() > 0


def test_a_long_authorization_url_survives_the_login_round_trip(idp):
    """AgentPG hostnames are long: the authorize URL an app sends the browser to passes 300 characters, and sign-in must still return to it."""
    long_next = "/oauth/authorize?" + "x=" + "a" * 900
    r = idp.post("/login", json={"username": "nobody", "password": "wrong-password", "next": long_next}, headers=CSRF)
    assert r.status_code == 401                                         # validated, not rejected as too long
    from identity import core
    assert core.safe_next(long_next) == long_next and core.safe_next("/" + "a" * 3000) == "/"
    assert core.safe_next("//evil.example") == "/" and core.safe_next("https://evil.example") == "/" and core.safe_next("/a\\b") == "/"


def test_another_replica_rotating_the_signing_key_is_noticed_within_the_cache_ttl(idp, monkeypatch):
    """The key cache is per process: a rotation done by another process must be picked up after keys.CACHE_TTL, not only at restart."""
    from identity import core, keys
    clock = [1000.0]
    monkeypatch.setattr(keys, "_now", lambda: clock[0])
    keys.forget()
    with core.db.connect() as conn:
        first = keys.signing_key(conn).kid
        assert keys.signing_key(conn).kid == first
        mine = dict(keys._cache)
        other = keys.rotate(conn)                              # "another replica" rotates (this also clears our cache)...
        keys._cache.update(mine)                               # ...so put back what a process that did not see it still holds
        clock[0] += keys.CACHE_TTL - 1
        assert keys.signing_key(conn).kid == first             # still inside the TTL: no database round trip is needed
        clock[0] += 2
        assert keys.signing_key(conn).kid == other             # past the TTL: the new active key
        assert keys.can_sign(conn)
