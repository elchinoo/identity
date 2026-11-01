"""Signing keys: RS256, generated here, stored encrypted under the vault key, published as a JWKS.

Rotation: a new key becomes active and signs from then on; the old one stays in the JWKS (status `retiring`) for 24 hours so
tokens already issued still verify, then is retired and dropped from it. Apps refetch the JWKS when they see an unknown `kid`.
"""
import threading
import time
from datetime import UTC, datetime, timedelta

from joserfc.jwk import RSAKey
from psycopg.types.json import Jsonb

from . import audit, core, rowmac
from .ids import new_kid

RETIRE_AFTER = timedelta(hours=24)
_lock = threading.Lock()
_cache: dict = {"kid": None, "key": None, "at": 0.0}
# Another replica may rotate the key. A process re-reads which key is active from the database at most this often, so it
# follows a rotation made elsewhere within CACHE_TTL seconds (the rotated-out key stays published for 24 hours, so nothing breaks).
CACHE_TTL = 30.0
_jwks_seen: dict = {"keys": []}                              # the last published set whose MACs all verified (used only while the vault is locked)
_now = time.monotonic                                       # tests replace this


def _generate(kid: str) -> RSAKey:
    return RSAKey.generate_key(2048, {"kid": kid, "use": "sig", "alg": "RS256"})


def _active(conn) -> dict | None:
    """The newest active key whose MAC verifies (a planted or edited row is as good as absent), or None."""
    for row in conn.execute("SELECT * FROM signing_key WHERE status='active' ORDER BY created_at DESC").fetchall():
        if rowmac.verify_row("signing_key", row):
            return row
    return None


def ensure(conn) -> str | None:
    """Make sure an active key exists. Needs the vault unlocked; returns the active kid or None when locked."""
    row = _active(conn)
    if row:
        if not _jwks_seen["keys"]:
            jwks(conn)                                         # remember what verifies, to keep publishing it if the vault is later locked
        return row["kid"]
    if not core.vault.is_unlocked():
        return None
    return rotate(conn, first=True)


def rotate(conn, first: bool = False) -> str:
    kid = new_kid()
    key = _generate(kid)
    rowmac.update(conn, "signing_key", "status='retiring', retire_at=%s", (datetime.now(UTC) + RETIRE_AFTER,), "status='active'")
    _insert(conn, kid, key)
    _retire_expired(conn)
    conn.commit()
    with _lock:
        _cache.update(kid=None, key=None, at=0.0)
    jwks(conn)
    return kid


def _insert(conn, kid: str, key: RSAKey) -> None:
    conn.execute("INSERT INTO signing_key (kid, alg, private_enc, public_jwk) VALUES (%s,'RS256',%s,%s)",
                 (kid, core.vault.encrypt(key.as_pem(private=True).decode(), core.CTX_SIGNING_KEY.format(kid=kid)), Jsonb(key.as_dict(private=False))))
    rowmac.seal(conn, "signing_key", "kid=%s", (kid,))


def _retire_expired(conn) -> None:
    rowmac.update(conn, "signing_key", "status='retired'", (), "status='retiring' AND retire_at < now()")


def emergency_rotate(conn, actor: str = "cli", reason: str = "") -> dict:
    """Hard revoke: a new key becomes active and EVERY earlier key is deleted at once (private half included), so the JWKS lists
    only the new key from this moment. Unlike `rotate`, nothing stays valid for a retire window: tokens signed by any earlier key
    fail verification as soon as a verifier refreshes its JWKS (the kit's TokenVerifier caches it for at most its `ttl`, 5 minutes by
    default), and every refresh token is revoked and every browser SSO session ended, so people sign in again. The local operator
    sessions (the admin console) are kept so the operator who runs this is not locked out. One transaction, audited."""
    kid = new_kid()
    key = _generate(kid)
    old = [r["kid"] for r in conn.execute("SELECT kid FROM signing_key").fetchall()]
    conn.execute("DELETE FROM signing_key")
    _insert(conn, kid, key)
    refresh = rowmac.update(conn, "oauth_refresh", "revoked_at = now()", (), "revoked_at IS NULL")
    codes = conn.execute("DELETE FROM oauth_code").rowcount
    sessions = conn.execute("DELETE FROM web_session WHERE source <> 'local'").rowcount
    detail = {"removed_keys": old, "refresh_tokens_revoked": refresh, "sso_sessions_ended": sessions, "codes_dropped": codes}
    if reason:
        detail["reason"] = reason[:200]
    audit.log(conn, actor, "signing_key_emergency_rotated", kid, **detail)
    conn.commit()
    forget()
    jwks(conn)
    return {"kid": kid, **detail}


def rotate_vault_key(conn, actor: str, password: str | None) -> dict[str, int]:
    """Replace the vault data key: every encrypted value (signing keys, federation secrets) is re-encrypted and the password and platform
    wraps rewritten in one transaction (agentpg-kit `Vault.rotate_data_key`). Needs the vault unlocked and, when an admin password
    exists, that password. Raises `VaultError` (wrong password, locked) without changing anything. Other replicas keep the old key in
    memory until restarted. The audit row carries counts only, never a secret."""
    snap = rowmac.snapshot(conn)                               # rows that verify under the old key: every MAC changes with the data key
    conn.rollback()                                            # rotate_data_key needs an idle connection
    counts = core.vault.rotate_data_key(conn, password=password)
    rowmac.reseal(conn, snap)                                  # signed again under the new key (rows that did not verify stay unsigned)
    audit.log(conn, actor, "vault_key_rotated", "", **counts)
    conn.commit()
    forget()
    return counts


def signing_key(conn) -> RSAKey:
    """The active private key: decrypted once and cached in memory; the active kid is re-checked in the database every CACHE_TTL seconds."""
    with _lock:
        if _cache["key"] is not None and _now() - _cache["at"] < CACHE_TTL:
            return _cache["key"]
    row = _active(conn)
    if not row:
        raise RuntimeError("no signing key: unlock the vault (sign in as the admin or set IDENTITY_ENCRYPTION_KEY)")
    with _lock:
        if _cache["key"] is not None and _cache["kid"] == row["kid"]:       # still the same key: just start a new interval
            _cache["at"] = _now()
            return _cache["key"]
    ctx = core.CTX_SIGNING_KEY.format(kid=row["kid"])
    pem = core.vault.decrypt(row["private_enc"], ctx)
    if core.vault.is_legacy(row["private_enc"]):                 # written before contexts: bind it to its row now (read-through upgrade)
        conn.execute("UPDATE signing_key SET private_enc=%s WHERE kid=%s AND private_enc=%s", (core.vault.encrypt(pem, ctx), row["kid"], row["private_enc"]))
        conn.commit()
    key = RSAKey.import_key(pem, {"kid": row["kid"], "use": "sig", "alg": "RS256"})
    with _lock:
        _cache.update(kid=row["kid"], key=key, at=_now())
    return key


def forget() -> None:
    with _lock:
        _cache.update(kid=None, key=None, at=0.0)


def jwks(conn) -> dict:
    if not core.vault.is_unlocked():                           # MACs cannot be checked: serve only what this process last verified (nothing after a cold start)
        return {"keys": list(_jwks_seen["keys"])}
    _retire_expired(conn)
    rows = conn.execute("SELECT * FROM signing_key WHERE status IN ('active', 'retiring') ORDER BY created_at DESC").fetchall()
    conn.commit()
    out = [r["public_jwk"] for r in rowmac.valid("signing_key", rows)]
    _jwks_seen["keys"] = out
    return {"keys": out}


def list_keys(conn) -> list[dict]:
    return conn.execute("SELECT kid, alg, status, created_at, retire_at FROM signing_key ORDER BY created_at DESC").fetchall()


def can_sign(conn) -> bool:
    """True if a token could be signed right now: an active key exists and its private half is readable (cached or vault unlocked)."""
    kid = ensure(conn)
    if kid is None:
        return False
    with _lock:
        if _cache["key"] is not None and _cache["kid"] == kid:
            return True
    return core.vault.is_unlocked()
