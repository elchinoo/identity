import base64
import hashlib
import os
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

TEST_URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="set TEST_DATABASE_URL to run database tests")
BASE = "http://localhost"
CSRF = {"X-Identity-CSRF": "1"}
PASSWORD = "correct horse battery staple"  # pragma: allowlist secret


def pytest_collection_modifyitems(config, items):
    if not TEST_URL:
        skip = pytest.mark.skip(reason="set TEST_DATABASE_URL to run database tests")
        for item in items:
            item.add_marker(skip)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", TEST_URL)
    for name in ("IDENTITY_API_KEY", "IDENTITY_ENCRYPTION_KEY", "IDENTITY_ISSUER", "IDENTITY_PUBLIC_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("IDENTITY_API_KEY_FILE", "/nonexistent")
    monkeypatch.setenv("IDENTITY_ENCRYPTION_KEY_FILE", "/nonexistent")


@pytest.fixture
def idp(env):
    """The identity app on a clean database, with its admin set up (so the vault is unlocked and a signing key exists)."""
    from identity import api, cli, core, keys
    with core.db.connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    cli.run_migrations()
    core.vault.lock()
    core.local._setup_code = None
    core.auth.limiter.clear()
    core.login_limiter.clear()
    keys.forget()
    api.reset_server()
    api._announced = True
    client = TestClient(api.app, base_url=BASE)
    r = client.post("/api/setup", json={"code": core.local.setup_code(), "password": PASSWORD}, headers=CSRF)
    assert r.status_code == 200, r.text
    client.admin = lambda: client                                    # the admin cookie lives on this client
    yield client
    core.vault.lock()
    core.db.close_pool()


class Proxy(httpx.BaseTransport):
    """Lets a kit TokenVerifier / RelyingParty talk to the app under test as if over the network."""

    def __init__(self, client):
        self.client = client

    def handle_request(self, request):
        r = self.client.request(request.method, request.url.path, content=request.content, headers={k: v for k, v in request.headers.items() if k.lower() != "host"})
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)


def http_for(client):
    return lambda: httpx.Client(transport=Proxy(client), base_url=BASE, follow_redirects=False)


def pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def make_world(idp):
    """An app `demo` (web) with roles, a service app, a user `ada` and the admin client used to build it."""
    h = CSRF
    r = idp.post("/api/apps", headers=h, json={"client_id": "demo", "name": "Demo", "kind": "web", "url": "https://demo.example.org",
                                              "redirect_uris": ["https://demo.example.org/auth/callback"], "post_logout_uris": ["https://demo.example.org/"],
                                              "roles": [{"name": "admin"}, {"name": "viewer"}, {"name": "approver"}], "default_roles": ["viewer"],
                                              "allowed_scopes": ["demo.write"]})
    assert r.status_code == 201, r.text
    secret = r.json()["client_secret"]
    r = idp.post("/api/apps", headers=h, json={"client_id": "other", "name": "Other", "kind": "web", "redirect_uris": ["https://other.example.org/cb"],
                                              "roles": [{"name": "admin"}]})
    assert r.status_code == 201
    r = idp.post("/api/apps", headers=h, json={"client_id": "robot", "name": "Robot", "kind": "service", "allowed_scopes": ["demo.write", "other.read", "robot.self"],
                                              "allowed_audiences": ["demo", "other"], "roles": []})
    assert r.status_code == 201
    robot_secret = r.json()["client_secret"]
    r = idp.post("/api/users", headers=h, json={"username": "ada", "email": "ada@example.org", "name": "Ada Lovelace", "password": "analytical engine 1843"})
    assert r.status_code == 201
    uid = r.json()["id"]
    return {"secret": secret, "robot_secret": robot_secret, "uid": uid}


def login_sso(idp, username="ada", password="analytical engine 1843"):
    """A separate browser (cookie jar) signed in as an ordinary person."""
    browser = TestClient(idp.app, base_url=BASE)
    r = browser.post("/login", json={"username": username, "password": password}, headers=CSRF)
    assert r.status_code == 200, r.text
    return browser


def authorize(browser, verifier_challenge, client_id="demo", redirect="https://demo.example.org/auth/callback", scope="openid profile email roles", state="st", nonce="n1", **extra):
    verifier, challenge = verifier_challenge
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "scope": scope, "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256", **extra}
    return browser.get("/oauth/authorize", params=params, follow_redirects=False)


def code_from(response):
    assert response.status_code == 302, (response.status_code, response.text)
    q = parse_qs(urlsplit(response.headers["location"]).query)
    assert "code" in q, response.headers["location"]
    return q["code"][0], q


def exchange(client, code, verifier, secret, client_id="demo", redirect="https://demo.example.org/auth/callback", grant="authorization_code", **extra):
    data = {"grant_type": grant, "code": code, "redirect_uri": redirect, "code_verifier": verifier, **extra}
    auth = (client_id, secret) if secret else None
    if not secret:
        data["client_id"] = client_id
    return client.post("/oauth/token", data=data, auth=auth)
