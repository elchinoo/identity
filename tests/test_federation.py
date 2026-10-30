"""Sign-in with Google and GitHub (mocked upstream), and the mapping of upstream identities onto local users."""
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
from conftest import BASE, CSRF, make_world
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from identity import federation

GOOGLE_KEY = RSAKey.generate_key(2048, {"kid": "g1", "use": "sig", "alg": "RS256"})


class Upstream:
    """Pretends to be Google (OIDC) and GitHub (OAuth 2.0)."""

    def __init__(self):
        self.google_claims = {"sub": "g-1", "email": "ada@example.org", "email_verified": True, "name": "Ada G"}
        self.github_user = {"id": 4242, "login": "ada-gh", "name": "Ada GH"}
        self.github_emails = [{"email": "ada@example.org", "primary": True, "verified": True}]
        self.last_nonce = None
        self.github_ok = True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if u == "https://accounts.google.com/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": "https://accounts.google.com", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                                             "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth", "token_endpoint": "https://oauth2.googleapis.com/token"})
        if u == "https://www.googleapis.com/oauth2/v3/certs":
            return httpx.Response(200, json={"keys": [GOOGLE_KEY.as_dict(private=False)]})
        if u == "https://oauth2.googleapis.com/token":
            body = parse_qs(request.content.decode())
            claims = {"iss": "https://accounts.google.com", "aud": "g-client", "exp": int(time.time()) + 300, "nonce": self.last_nonce, **self.google_claims}
            return httpx.Response(200, json={"id_token": jwt.encode({"alg": "RS256", "kid": "g1"}, claims, GOOGLE_KEY), "access_token": "x", "code_seen": body["code"]})
        if u == federation.GITHUB_TOKEN:
            return httpx.Response(200, json={"access_token": "ghtok"} if self.github_ok else {"error": "bad_verification_code"})
        if u == f"{federation.GITHUB_API}/user":
            return httpx.Response(200, json=self.github_user)
        if u == f"{federation.GITHUB_API}/user/emails":
            return httpx.Response(200, json=self.github_emails)
        return httpx.Response(404)


def setup(idp, monkeypatch, **provider):
    w = make_world(idp)
    up = Upstream()
    monkeypatch.setattr(federation, "http_factory", lambda: httpx.Client(transport=httpx.MockTransport(up), follow_redirects=False))
    for name in ("google", "github"):
        r = idp.put(f"/api/federation/{name}", headers=CSRF, json={"client_id": "g-client" if name == "google" else "gh-client", "client_secret": "upstream-secret", **provider})
        assert r.status_code == 200, r.text
    return w, up


def signin(idp, up, provider="google", **kw):
    """Run the redirect dance as a browser would. Returns the final response of the callback."""
    browser = TestClient(idp.app, base_url=BASE)
    start = browser.get(f"/login/{provider}", params={"next": "/apps"}, follow_redirects=False)
    assert start.status_code == 303, start.text
    q = parse_qs(urlsplit(start.headers["location"]).query)
    up.last_nonce = q.get("nonce", [None])[0]
    cb = browser.get(f"/login/{provider}/callback", params={"code": "upstream-code", "state": kw.get("state", q["state"][0])}, follow_redirects=False)
    return browser, start, cb


def test_provider_secret_is_encrypted_and_never_returned(idp, monkeypatch):
    setup(idp, monkeypatch)
    text = idp.get("/api/federation").text
    assert "upstream-secret" not in text and "client_secret" not in text
    from identity import core
    with core.db.connect() as c:
        enc = c.execute("SELECT client_secret_enc FROM federation_provider WHERE provider='google'").fetchone()["client_secret_enc"]
    assert "upstream-secret" not in enc
    assert idp.get("/api/login-options").json()["providers"] == [{"provider": "github", "label": "GitHub"}, {"provider": "google", "label": "Google"}]


def test_google_signs_in_an_existing_user_by_verified_email(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    browser, start, cb = signin(idp, up)
    assert start.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?") and "code_challenge_method=S256" in start.headers["location"]
    assert cb.status_code == 303 and cb.headers["location"] == "/apps" and "idp_sso" in cb.cookies
    me = browser.get("/api/my-apps").json()
    assert me["user"]["username"] == "ada"
    from identity import core
    with core.db.connect() as c:
        row = c.execute("SELECT user_id FROM idp_federated WHERE provider='google' AND subject='g-1'").fetchone()
    assert row["user_id"] == w["uid"]


def test_unverified_email_never_links_and_unknown_people_are_refused(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    up.google_claims = {"sub": "g-2", "email": "ada@example.org", "email_verified": False, "name": "Impostor"}
    _, _, cb = signin(idp, up)
    assert cb.status_code == 303 and cb.headers["location"].startswith("/login?error=") and "idp_sso" not in cb.cookies
    up.google_claims = {"sub": "g-3", "email": "stranger@example.org", "email_verified": True, "name": "Stranger"}
    _, _, cb = signin(idp, up)
    assert cb.headers["location"].startswith("/login?error=") and "idp_sso" not in cb.cookies
    from identity import core
    with core.db.connect() as c:
        assert c.execute("SELECT count(*) AS n FROM idp_user").fetchone()["n"] == 1             # nobody was created
        assert c.execute("SELECT count(*) AS n FROM idp_federated").fetchone()["n"] == 0


def test_open_mode_creates_users_only_for_allowed_domains(idp, monkeypatch):
    w, up = setup(idp, monkeypatch, mode="open", allowed_domains=["example.org"], default_groups=[])
    up.google_claims = {"sub": "g-9", "email": "newbie@example.org", "email_verified": True, "name": "New Bie"}
    browser, _, cb = signin(idp, up)
    assert cb.headers["location"] == "/apps" and browser.get("/api/my-apps").json()["user"]["email"] == "newbie@example.org"
    up.google_claims = {"sub": "g-10", "email": "outsider@evil.example", "email_verified": True, "name": "Out Sider"}
    _, _, cb = signin(idp, up)
    assert cb.headers["location"].startswith("/login?error=")
    r = idp.put("/api/federation/google", headers=CSRF, json={"client_id": "g-client", "mode": "open", "allowed_domains": []})
    assert r.status_code == 422                                                                     # open mode needs a domain allow-list


def test_a_disabled_user_cannot_sign_in_upstream(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    idp.patch(f"/api/users/{w['uid']}", headers=CSRF, json={"status": "disabled"})
    _, _, cb = signin(idp, up)
    assert cb.headers["location"].startswith("/login?error=") and "idp_sso" not in cb.cookies


def test_the_state_is_single_use_and_the_nonce_is_checked(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    browser = TestClient(idp.app, base_url=BASE)
    start = browser.get("/login/google", follow_redirects=False)
    q = parse_qs(urlsplit(start.headers["location"]).query)
    up.last_nonce = "a-different-nonce"                                                              # an ID token minted for another login
    bad = browser.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert bad.headers["location"].startswith("/login?error=") and "idp_sso" not in bad.cookies
    again = browser.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert again.headers["location"].startswith("/login?error=")                                     # the state is gone
    forged = browser.get("/login/google/callback", params={"code": "c", "state": "made-up"}, follow_redirects=False)
    assert forged.headers["location"].startswith("/login?error=")
    assert browser.get("/login/google/callback", follow_redirects=False).headers["location"].startswith("/login?error=")


def test_github_signs_in_with_its_primary_verified_email(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    browser, start, cb = signin(idp, up, "github")
    assert start.headers["location"].startswith(federation.GITHUB_AUTHORIZE) and "code_challenge_method=S256" in start.headers["location"]
    assert cb.headers["location"] == "/apps" and browser.get("/api/my-apps").json()["user"]["username"] == "ada"
    up.github_emails = [{"email": "ada@example.org", "primary": False, "verified": True}, {"email": "x@example.org", "primary": True, "verified": False}]
    up.github_user = {"id": 7, "login": "other", "name": "Other"}
    _, _, cb = signin(idp, up, "github")
    assert cb.headers["location"].startswith("/login?error=")                                         # no primary verified address: no linking
    up.github_ok = False
    _, _, cb = signin(idp, up, "github")
    assert cb.headers["location"].startswith("/login?error=")


def test_disabled_or_unconfigured_providers_are_not_offered(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    idp.put("/api/federation/github", headers=CSRF, json={"client_id": "gh-client", "enabled": False})
    assert [p["provider"] for p in idp.get("/api/login-options").json()["providers"]] == ["google"]
    r = TestClient(idp.app, base_url=BASE).get("/login/github", follow_redirects=False)
    assert r.headers["location"].startswith("/login?error=")
    assert TestClient(idp.app, base_url=BASE).get("/login/nope", follow_redirects=False).headers["location"].startswith("/login?error=")
    assert json.loads(json.dumps(idp.get("/api/federation").json()))["available"] == {"google": "Google", "github": "GitHub"}


def test_state_is_bound_to_the_browser_that_started_the_login(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    victim_start = TestClient(idp.app, base_url=BASE).get("/login/google", follow_redirects=False)
    cookie = victim_start.headers["set-cookie"].lower()
    assert "apg_oidc_bind=" in cookie and "httponly" in cookie and "samesite=lax" in cookie and "max-age=600" in cookie and "path=/" in cookie
    assert "idp_fed" not in cookie                                                        # one mechanism: the kit's binding cookie
    attacker = TestClient(idp.app, base_url=BASE)
    start = attacker.get("/login/google", follow_redirects=False)
    q = parse_qs(urlsplit(start.headers["location"]).query)
    up.last_nonce = q["nonce"][0]
    # the attacker's state delivered to a different browser (no cookie, or somebody else's cookie) is refused and never signs in
    other = TestClient(idp.app, base_url=BASE)
    r = other.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"].startswith("/login?error=") and "idp_sso" not in r.cookies
    other.get("/login/google", follow_redirects=False)                                    # now with a cookie, but for another state
    r = other.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"].startswith("/login?error=") and "idp_sso" not in r.cookies
    # a refused callback consumes the state (single use), so the stolen state is dead for the genuine browser too
    r = attacker.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"].startswith("/login?error=") and "idp_sso" not in r.cookies
    # a fresh attempt in the genuine browser completes, clears the binding cookie, and cannot be replayed
    start = attacker.get("/login/google", follow_redirects=False)
    q = parse_qs(urlsplit(start.headers["location"]).query)
    up.last_nonce = q["nonce"][0]
    r = attacker.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/" and "idp_sso" in r.cookies
    assert "apg_oidc_bind" not in attacker.cookies
    again = attacker.get("/login/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert again.headers["location"].startswith("/login?error=")


def test_forwarded_allow_ips_is_never_a_wildcard_by_default(monkeypatch):
    from identity import cli
    monkeypatch.delenv("IDENTITY_FORWARDED_ALLOW_IPS", raising=False)
    assert cli.forwarded_allow_ips() == "127.0.0.1"
    monkeypatch.setenv("IDENTITY_FORWARDED_ALLOW_IPS", "10.1.2.3")
    assert cli.forwarded_allow_ips() == "10.1.2.3"


def test_callback_without_the_binding_cookie_is_refused_for_google_and_github(idp, monkeypatch):
    w, up = setup(idp, monkeypatch)
    for provider in ("google", "github"):
        browser = TestClient(idp.app, base_url=BASE)
        start = browser.get(f"/login/{provider}", follow_redirects=False)
        q = parse_qs(urlsplit(start.headers["location"]).query)
        up.last_nonce = q.get("nonce", ["-"])[0]
        stranger = TestClient(idp.app, base_url=BASE)                                      # no cookie at all
        r = stranger.get(f"/login/{provider}/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
        assert r.headers["location"].startswith("/login?error=") and "idp_sso" not in r.cookies
        # the state was consumed by that refusal: even the genuine browser cannot reuse it
        again = browser.get(f"/login/{provider}/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
        assert again.headers["location"].startswith("/login?error=") and "idp_sso" not in again.cookies
        # a forged cookie value is refused as well
        start = browser.get(f"/login/{provider}", follow_redirects=False)
        q = parse_qs(urlsplit(start.headers["location"]).query)
        up.last_nonce = q.get("nonce", ["-"])[0]
        browser.cookies.set("apg_oidc_bind", "0" * 64)
        bad = browser.get(f"/login/{provider}/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
        assert bad.headers["location"].startswith("/login?error=") and "idp_sso" not in bad.cookies
