"""The development-only http transport relaxation: decided from configuration (issuer + IDENTITY_DEV_HTTP), never from request headers."""
import pytest
from conftest import CSRF, authorize, code_from, exchange, make_world, pkce
from fastapi.testclient import TestClient

from identity import core

DEV = "http://identity.localhost"


@pytest.mark.parametrize("issuer", ["http://localhost:8000", "http://identity.localhost", "http://a.b.localhost:9000/", "http://127.0.0.1:8000", "http://[::1]:8000", "HTTP://LocalHost"])
def test_loopback_http_issuer_with_flag_is_relaxed(issuer):
    assert core.dev_http_relaxed(issuer, True) is True


@pytest.mark.parametrize("issuer", ["https://localhost", "https://identity.localhost", "https://127.0.0.1", "https://[::1]"])
def test_https_issuer_never_relaxed_even_with_flag_and_loopback(issuer):
    assert core.dev_http_relaxed(issuer, True) is False


@pytest.mark.parametrize("issuer", ["http://identity.example.org", "http://10.0.0.5", "http://localhost.evil.org", "http://evil-localhost", "http://notlocalhost",
                                    "http://127.0.0.1.evil.org", "http://0.0.0.0", "http://localhost@evil.org", "", "not a url"])
def test_http_non_loopback_issuer_never_relaxed(issuer):
    assert core.dev_http_relaxed(issuer, True) is False


@pytest.mark.parametrize("issuer", ["http://localhost", "http://identity.localhost", "http://127.0.0.1", "http://[::1]"])
def test_loopback_issuer_without_flag_not_relaxed(issuer):
    assert core.dev_http_relaxed(issuer, False) is False


def test_flag_and_issuer_come_from_configuration(monkeypatch):
    monkeypatch.delenv("IDENTITY_ISSUER", raising=False)
    monkeypatch.delenv("IDENTITY_PUBLIC_URL", raising=False)
    monkeypatch.setenv("IDENTITY_DEV_HTTP", "1")
    assert core.dev_http_relaxed() is False                       # no configured issuer: nothing is guessed from a request
    monkeypatch.setenv("IDENTITY_PUBLIC_URL", DEV)
    assert core.dev_http_relaxed() is True
    monkeypatch.setenv("IDENTITY_ISSUER", "https://id.example.org")   # IDENTITY_ISSUER wins, as in core.issuer
    assert core.dev_http_relaxed() is False
    monkeypatch.setenv("IDENTITY_ISSUER", DEV)
    monkeypatch.setenv("IDENTITY_DEV_HTTP", "0")
    assert core.dev_http_relaxed() is False


def test_oauth_uri_only_rewritten_while_relaxed(monkeypatch):
    monkeypatch.setenv("IDENTITY_ISSUER", DEV)
    monkeypatch.setenv("IDENTITY_DEV_HTTP", "1")
    assert core.oauth_uri("http://identity.localhost/oauth/token") == "https://identity.localhost/oauth/token"
    monkeypatch.delenv("IDENTITY_DEV_HTTP")
    assert core.oauth_uri("http://identity.localhost/oauth/token") == "http://identity.localhost/oauth/token"


def test_spoofed_host_and_forwarded_headers_are_ignored(monkeypatch):
    monkeypatch.setenv("IDENTITY_ISSUER", "https://id.example.org")
    monkeypatch.setenv("IDENTITY_DEV_HTTP", "1")
    assert core.dev_http_relaxed() is False
    assert core.oauth_uri("http://id.example.org/oauth/token") == "http://id.example.org/oauth/token"   # a spoofed Host/X-Forwarded-* cannot matter: not an input


# ---- integration -------------------------------------------------------------------------------------------------------------------
def dev_world(idp, monkeypatch, flag):
    from identity import api
    w = make_world(idp)
    monkeypatch.setenv("IDENTITY_ISSUER", DEV)
    if flag:
        monkeypatch.setenv("IDENTITY_DEV_HTTP", "1")
    else:
        monkeypatch.delenv("IDENTITY_DEV_HTTP", raising=False)
    api.reset_server()
    return w, TestClient(api.app, base_url=DEV)


def test_flow_over_http_localhost_name_with_flag(idp, monkeypatch):
    w, client = dev_world(idp, monkeypatch, True)
    browser = TestClient(idp.app, base_url=DEV)
    assert browser.post("/login", json={"username": "ada", "password": "analytical engine 1843"}, headers=CSRF).status_code == 200
    pk = pkce()
    code, _ = code_from(authorize(browser, pk))
    r = exchange(client, code, pk[0], w["secret"])
    assert r.status_code == 200, r.text
    assert r.json()["access_token"] and r.json()["id_token"]
    r = client.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "demo.write"}, auth=("robot", w["robot_secret"]))
    assert r.status_code == 200, r.text
    assert client.get("/readyz").json()["insecure_transport_relaxed"] is True


def test_without_flag_refused_cleanly_not_500(idp, monkeypatch):
    w, client = dev_world(idp, monkeypatch, False)
    r = client.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "demo.write"}, auth=("robot", w["robot_secret"]))
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "insecure_transport"
    assert client.get("/readyz").json()["insecure_transport_relaxed"] is False


def test_https_issuer_with_flag_is_not_relaxed(idp, monkeypatch):
    from identity import api
    w, client = dev_world(idp, monkeypatch, True)
    monkeypatch.setenv("IDENTITY_ISSUER", "https://identity.localhost")
    api.reset_server()
    r = client.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "demo.write"}, auth=("robot", w["robot_secret"]))
    assert r.status_code == 400 and r.json()["error"] == "insecure_transport"
    assert client.get("/readyz").json()["insecure_transport_relaxed"] is False


def test_readyz_field_present_by_default(idp):
    assert idp.get("/readyz").json()["insecure_transport_relaxed"] is False
