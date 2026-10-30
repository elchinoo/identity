"""Signing keys: RS256, generated here, stored encrypted under the vault key, published as a JWKS.

Rotation: a new key becomes active and signs from then on; the old one stays in the JWKS (status `retiring`) for 24 hours so
tokens already issued still verify, then is retired and dropped from it. Apps refetch the JWKS when they see an unknown `kid`.
"""
import threading
import time
from datetime import UTC, datetime, timedelta

from joserfc.jwk import RSAKey
from psycopg.types.json import Jsonb

from . import audit, core
from .ids import new_kid

RETIRE_AFTER = timedelta(hours=24)
_lock = threading.Lock()
_cache: dict = {"kid": None, "key": None, "at": 0.0}
# Another replica may rotate the key. A process re-reads which key is active from the database at most this often, so it
# follows a rotation made elsewhere within CACHE_TTL seconds (the rotated-out key stays published for 24 hours, so nothing breaks).
CACHE_TTL = 30.0
_now = time.monotonic                                       # tests replace this


def _generate(kid: str) -> RSAKey:
    return RSAKey.generate_key(2048, {"kid": kid, "use": "sig", "alg": "RS256"})


def ensure(conn) -> str | None:
    """Make sure an active key exists. Needs the vault unlocked; returns the active kid or None when locked."""
    row = conn.execute("SELECT kid FROM signing_key WHERE status='active' ORDER BY created_at DESC LIMIT 1").fetchone()
    if row:
        return row["kid"]
    if not core.vault.is_unlocked():
        return None
    return rotate(conn, first=True)


def rotate(conn, first: bool = False) -> str:
    kid = new_kid()
    key = _generate(kid)
    conn.execute("UPDATE signing_key SET status='retiring', retire_at=%s WHERE status='active'", (datetime.now(UTC) + RETIRE_AFTER,))
    conn.execute("INSERT INTO signing_key (kid, alg, private_enc, public_jwk) VALUES (%s,'RS256',%s,%s)",
                 (kid, core.vault.encrypt(key.as_pem(private=True).decode()), Jsonb(key.as_dict(private=False))))
    conn.execute("UPDATE signing_key SET status='retired' WHERE status='retiring' AND retire_at < now()")
    conn.commit()
    with _lock:
        _cache.update(kid=None, key=None, at=0.0)
    return kid


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
    conn.execute("INSERT INTO signing_key (kid, alg, private_enc, public_jwk) VALUES (%s,'RS256',%s,%s)",
                 (kid, core.vault.encrypt(key.as_pem(private=True).decode()), Jsonb(key.as_dict(private=False))))
    refresh = conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE revoked_at IS NULL").rowcount
    codes = conn.execute("DELETE FROM oauth_code").rowcount
    sessions = conn.execute("DELETE FROM web_session WHERE source <> 'local'").rowcount
    detail = {"removed_keys": old, "refresh_tokens_revoked": refresh, "sso_sessions_ended": sessions, "codes_dropped": codes}
    if reason:
        detail["reason"] = reason[:200]
    audit.log(conn, actor, "signing_key_emergency_rotated", kid, **detail)
    conn.commit()
    forget()
    return {"kid": kid, **detail}


def signing_key(conn) -> RSAKey:
    """The active private key: decrypted once and cached in memory; the active kid is re-checked in the database every CACHE_TTL seconds."""
    with _lock:
        if _cache["key"] is not None and _now() - _cache["at"] < CACHE_TTL:
            return _cache["key"]
    row = conn.execute("SELECT kid, private_enc FROM signing_key WHERE status='active' ORDER BY created_at DESC LIMIT 1").fetchone()
    if not row:
        raise RuntimeError("no signing key: unlock the vault (sign in as the admin or set IDENTITY_ENCRYPTION_KEY)")
    with _lock:
        if _cache["key"] is not None and _cache["kid"] == row["kid"]:       # still the same key: just start a new interval
            _cache["at"] = _now()
            return _cache["key"]
    key = RSAKey.import_key(core.vault.decrypt(row["private_enc"]), {"kid": row["kid"], "use": "sig", "alg": "RS256"})
    with _lock:
        _cache.update(kid=row["kid"], key=key, at=_now())
    return key


def forget() -> None:
    with _lock:
        _cache.update(kid=None, key=None, at=0.0)


def jwks(conn) -> dict:
    conn.execute("UPDATE signing_key SET status='retired' WHERE status='retiring' AND retire_at < now()")
    rows = conn.execute("SELECT public_jwk FROM signing_key WHERE status IN ('active', 'retiring') ORDER BY created_at DESC").fetchall()
    conn.commit()
    return {"keys": [r["public_jwk"] for r in rows]}


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
