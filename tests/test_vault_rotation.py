"""Vault v2: ciphertexts bound to their row, legacy values upgraded, data-key rotation (API, CLI, password-only mode), plus the
hardening defaults of the kit 0.4 (anonymous mode, static key length, scrypt busy)."""
import base64
import getpass

import pytest
from apgkit import passwords
from apgkit.auth import TokenVerifier
from apgkit.vault import VaultError
from conftest import (
    BASE,
    CSRF,
    PASSWORD,
    authorize,
    code_from,
    exchange,
    http_for,
    login_sso,
    make_world,
    pkce,
)
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from identity import cli, core, keys


def anon(idp):
    return TestClient(idp.app, base_url=BASE)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def issue(idp, w):
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope="openid"))
    return exchange(idp, code, pk[0], w["secret"]).json()["access_token"]


def verifier(idp):
    return TokenVerifier(BASE, "demo", http=http_for(idp))


def put_provider(idp):
    r = idp.put("/api/federation/github", headers=CSRF, json={"client_id": "gh", "client_secret": "upstream-secret-value"})
    assert r.status_code == 200, r.text


def row(sql, *args):
    with core.db.connect() as c:
        return c.execute(sql, args).fetchone()


def legacy(plain):
    """A value as written before contexts existed: a Fernet token under the data key."""
    return Fernet(base64.urlsafe_b64encode(core.vault._data_key)).encrypt(plain.encode()).decode()


def test_secrets_are_bound_to_their_rows(idp):
    put_provider(idp)
    enc = row("SELECT client_secret_enc FROM federation_provider")["client_secret_enc"]
    kid = row("SELECT kid FROM signing_key WHERE status='active'")["kid"]
    pem = row("SELECT private_enc FROM signing_key WHERE kid=%s", kid)["private_enc"]
    assert enc.startswith("v2$") and pem.startswith("v2$")
    assert core.vault.decrypt(enc, core.CTX_PROVIDER_SECRET.format(provider="github")) == "upstream-secret-value"
    with pytest.raises(VaultError):
        core.vault.decrypt(enc, "")                                     # no context
    with pytest.raises(VaultError):
        core.vault.decrypt(enc, core.CTX_PROVIDER_SECRET.format(provider="google"))   # another row
    with pytest.raises(VaultError):
        core.vault.decrypt(pem, core.CTX_PROVIDER_SECRET.format(provider="github"))   # another column
    assert set(core.vault.stores()) >= {"signing_key", "federation_provider"}


def test_rows_written_before_contexts_still_open_and_are_upgraded_on_read(idp):
    w = make_world(idp)
    put_provider(idp)
    with core.db.connect() as c:
        kid = keys.ensure(c)
        pem = core.vault.decrypt(c.execute("SELECT private_enc FROM signing_key WHERE kid=%s", (kid,)).fetchone()["private_enc"],
                                 core.CTX_SIGNING_KEY.format(kid=kid))
        c.execute("UPDATE signing_key SET private_enc=%s WHERE kid=%s", (legacy(pem), kid))
        c.execute("UPDATE federation_provider SET client_secret_enc=%s", (legacy("upstream-secret-value"),))
        c.commit()
    keys.forget()
    assert verifier(idp).verify(issue(idp, w))["sub"]                   # signs with the legacy-stored key
    assert row("SELECT private_enc FROM signing_key WHERE kid=%s", kid)["private_enc"].startswith("v2$")
    from identity import federation
    with core.db.connect() as c:
        cfg = c.execute("SELECT * FROM federation_provider WHERE provider='github'").fetchone()
        assert federation._secret(c, cfg) == "upstream-secret-value"
    assert row("SELECT client_secret_enc FROM federation_provider")["client_secret_enc"].startswith("v2$")


def test_rotation_through_the_api_needs_the_password_and_confirmation(idp, monkeypatch):
    w = make_world(idp)
    put_provider(idp)
    before = issue(idp, w)
    old_pem = row("SELECT private_enc FROM signing_key")["private_enc"]
    url = "/api/vault/rotate-key"
    assert idp.post(url, headers=CSRF, json={"password": PASSWORD}).status_code == 422                       # no confirm
    assert idp.post(url, headers=CSRF, json={"confirm": True, "password": "wrong password here"}).status_code == 403
    assert idp.post(url, headers=CSRF, json={"confirm": True}).status_code == 403                             # a session alone is not enough
    assert anon(idp).post(url, headers=CSRF, json={"confirm": True, "password": PASSWORD}).status_code == 401
    monkeypatch.setenv("IDENTITY_DEPLOY_KEY", "deploy-key-for-tests-0123456789-abcdef")
    assert anon(idp).post(url, headers=bearer("deploy-key-for-tests-0123456789-abcdef"), json={"confirm": True, "password": PASSWORD}).status_code == 403
    assert row("SELECT private_enc FROM signing_key")["private_enc"] == old_pem                              # nothing changed so far
    r = idp.post(url, headers=CSRF, json={"confirm": True, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["restart_other_replicas"] and r.json()["rotated"]["signing_key"] >= 1
    assert row("SELECT private_enc FROM signing_key")["private_enc"] != old_pem
    audit = idp.get("/api/audit").json()[0]
    assert audit["action"] == "vault_key_rotated" and "upstream-secret" not in str(audit) and PASSWORD not in str(audit)
    assert verifier(idp).verify(before)["sub"] and verifier(idp).verify(issue(idp, w))["sub"]


def test_password_only_vault_unlocks_signs_rotates_and_keeps_old_tokens_valid(idp):
    """No IDENTITY_ENCRYPTION_KEY (the fixture's mode): only the admin password opens the vault."""
    w = make_world(idp)
    put_provider(idp)
    with core.db.connect() as c:
        assert core.vault.has_password_wrap(c) and not core.vault._env_secret()
    before = issue(idp, w)
    kid_before = row("SELECT kid FROM signing_key WHERE status='active'")["kid"]
    core.vault.lock()
    keys.forget()
    assert anon(idp).get("/readyz").status_code == 503                                                         # locked: nobody can sign
    with core.db.connect() as c:
        assert core.vault.unlock_with_password(c, PASSWORD)
        stored = c.execute("SELECT private_enc FROM signing_key WHERE kid=%s", (kid_before,)).fetchone()["private_enc"]
        c.commit()
        counts = keys.rotate_vault_key(c, "test", PASSWORD)
        assert counts["signing_key"] >= 1 and counts["federation_provider"] == 1
        assert c.execute("SELECT private_enc FROM signing_key WHERE kid=%s", (kid_before,)).fetchone()["private_enc"] != stored
    # same RSA key, new envelope: tokens issued before the rotation still verify, and a new one is signed by the same key
    assert verifier(idp).verify(before)["sub"]
    after = issue(idp, w)
    assert verifier(idp).verify(after)["sub"] and row("SELECT kid FROM signing_key WHERE status='active'")["kid"] == kid_before
    # a restart: the old data key is gone from memory, the password still opens the (re-wrapped) new one
    core.vault.lock()
    keys.forget()
    assert not core.vault.is_unlocked()
    with core.db.connect() as c:
        assert not core.vault.unlock_with_password(c, "not the password at all")
        assert core.vault.unlock_with_password(c, PASSWORD)
    assert verifier(idp).verify(issue(idp, w))["sub"] and verifier(idp).verify(before)["sub"]
    with core.db.connect() as c:                                                                               # the provider secret survived too
        cfg = c.execute("SELECT * FROM federation_provider WHERE provider='github'").fetchone()
        assert core.vault.decrypt(cfg["client_secret_enc"], core.CTX_PROVIDER_SECRET.format(provider="github")) == "upstream-secret-value"


def test_rotate_vault_key_cli_asks_for_the_password(idp, monkeypatch, capsys):
    w = make_world(idp)
    before = issue(idp, w)
    assert cli.main(["rotate-vault-key"]) == 2                                                                 # needs --yes
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "wrong password here")
    old = row("SELECT private_enc FROM signing_key")["private_enc"]
    assert cli.main(["rotate-vault-key", "--yes"]) == 1
    assert row("SELECT private_enc FROM signing_key")["private_enc"] == old
    core.vault.lock()                                                                                          # a fresh process: locked
    keys.forget()
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PASSWORD)
    assert cli.main(["rotate-vault-key", "--yes"]) == 0
    assert "Restart every other identity replica" in capsys.readouterr().out
    assert row("SELECT private_enc FROM signing_key")["private_enc"] != old
    assert row("SELECT action FROM idp_audit ORDER BY id DESC LIMIT 1")["action"] == "vault_key_rotated"
    assert verifier(idp).verify(before)["sub"] and verifier(idp).verify(issue(idp, w))["sub"]


def test_anonymous_mode_is_honoured_only_on_loopback(idp, monkeypatch):
    monkeypatch.setenv("IDENTITY_ALLOW_ANONYMOUS", "1")
    monkeypatch.delenv("IDENTITY_ALLOW_ANONYMOUS_PUBLIC", raising=False)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("IDENTITY_HOST", raising=False)
    assert core.bind_host() == "0.0.0.0"                                                                       # the serve default is public
    monkeypatch.setattr(core.auth, "bind_host", core.bind_host())
    assert anon(idp).get("/api/apps").status_code == 401
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setattr(core.auth, "bind_host", core.bind_host())
    assert anon(idp).get("/api/apps").status_code == 200                                                       # evaluated per request, not at import
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setattr(core.auth, "bind_host", core.bind_host())
    monkeypatch.setenv("IDENTITY_ALLOW_ANONYMOUS_PUBLIC", "1")
    assert anon(idp).get("/api/apps").status_code == 200


def test_a_short_static_admin_key_is_refused(idp, monkeypatch):
    monkeypatch.setenv("IDENTITY_API_KEY", "short-key-0123456789")                                              # 20 characters
    assert anon(idp).get("/api/apps", headers=bearer("short-key-0123456789")).status_code == 401
    monkeypatch.setenv("IDENTITY_API_KEY", "long-enough-admin-key-0123456789-abcdef")
    assert anon(idp).get("/api/apps", headers=bearer("long-enough-admin-key-0123456789-abcdef")).status_code == 200


def test_login_answers_503_when_every_scrypt_slot_is_taken(idp, monkeypatch):
    make_world(idp)

    def busy(*a, **k):
        raise passwords.ScryptBusy()
    monkeypatch.setattr(passwords, "verify_password", busy)
    r = anon(idp).post("/login", json={"username": "ada", "password": "analytical engine 1843"}, headers=CSRF)
    assert r.status_code == 503 and r.headers["retry-after"] == "1"
    assert core.login_limiter.limited("127.0.0.1") is False                                                    # a busy server is not a failed guess
