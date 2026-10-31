"""Sealed boot: with APGKIT_SEALED set the app serves nothing but the seal routes and health until the operator unseals it."""
import importlib
import os
import sys
import time

import pytest
from apgkit import sealed as sealing
from conftest import BASE, TEST_URL
from fastapi.testclient import TestClient

PASSPHRASE = "correct-horse-battery-staple-9"  # pragma: allowlist secret
STATIC_KEY = "k" * 40                           # pragma: allowlist secret


@pytest.fixture
def sealed_api(env, monkeypatch):
    """A fresh `identity.api` built with APGKIT_SEALED set (the app decides at import), put back afterwards."""
    import identity
    from identity import core
    with core.db.connect() as c:                             # an empty database: the first sealed start migrates and creates the vault
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    blob = sealing.seal({"DATABASE_URL": TEST_URL, "IDENTITY_API_KEY": STATIC_KEY}, PASSPHRASE)
    monkeypatch.setenv("APGKIT_SEALED", blob)
    monkeypatch.delenv("DATABASE_URL")                       # the only copy of the database URL is now inside the blob
    previous = sys.modules.pop("identity.api", None)
    core.vault.lock()
    try:
        yield importlib.import_module("identity.api")
    finally:
        sealing.set_active(None)
        core.vault.lock()
        core.db.close_pool()
        sys.modules.pop("identity.api", None)
        if previous is not None:
            sys.modules["identity.api"] = previous
            identity.api = previous


def test_sealed_app_is_closed_until_unsealed_then_works(sealed_api):
    from identity import core
    # Nothing in the environment: the static key and the database URL exist only in the blob.
    assert core.local.static_key() == ""
    with TestClient(sealed_api.app, base_url=BASE) as c:
        assert c.get("/healthz").status_code == 200
        assert c.get("/jwks.json").status_code == 503
        assert c.get("/api/apps", headers={"Authorization": f"Bearer {STATIC_KEY}"}).status_code == 503
        assert c.get("/_seal/status").json() == {"state": "sealed"}
        wrong = c.post("/_seal/unseal", json=sealing.make_envelope(c.get("/_seal/key").json()["public_key"], PASSPHRASE + "x"))
        assert wrong.status_code == 401

        # a clean database, reached through the sealed DATABASE_URL (the environment has none)
        assert "DATABASE_URL" not in os.environ
        r = c.post("/_seal/unseal", json=sealing.make_envelope(c.get("/_seal/key").json()["public_key"], PASSPHRASE))
        assert r.status_code == 200, r.text
        assert r.json() == {"state": "unsealed"}
        assert core.local.static_key() == STATIC_KEY               # read_secret answers from the blob

        for _ in range(60):                                        # the deferred lifespan migrates and makes the first signing key
            if c.get("/readyz").status_code == 200:
                break
            time.sleep(0.5)
        assert c.get("/readyz").status_code == 200
        assert c.get("/jwks.json").status_code == 200
        assert c.get("/api/apps", headers={"Authorization": f"Bearer {STATIC_KEY}"}).status_code == 200

        # the vault is wrapped under the passphrase only: no platform-secret wrap exists
        with core.db.connect() as conn:
            status = core.vault.status(conn)
        assert status["initialized"] and status["unlocked"] and not status["auto_unlock"]
        with core.db.connect() as conn:
            assert core.vault.has_password_wrap(conn)


def test_nothing_changes_without_a_blob(idp):
    assert idp.get("/healthz").status_code == 200
    assert idp.get("/jwks.json").status_code == 200
