"""Row MACs: a database WRITE without the vault data key cannot forge identities, widen privileges, redirect codes or publish signing keys.

Every security-relevant row carries `mac`, an HMAC under a subkey of the vault data key (agentpg-kit `Vault.row_mac`) over the fields
listed in FIELDS. Reads that feed an authorization or token decision call `verify_row`; a row with a missing or wrong MAC is treated
exactly like a missing row. Writes sign in the same transaction (`seal`, `update`).

Limits (see README, "Row MACs"): a copied older authentic row replays from a backup; deleting rows is still possible; unsigned rows are
ignored, so an attacker's write can at worst deny service. Verification needs the vault open and fails closed (False) when it is locked.
"""
import json
import logging
import threading
from datetime import datetime

from prometheus_client import Counter

from . import core

log = logging.getLogger("identity.rowmac")

# column kinds: s text/number, arr text[] (sorted), json jsonb (sort_keys), ts timestamptz (epoch seconds), bool (0/1)
FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "idp_user": (("id", "s"), ("username", "s"), ("email", "s"), ("password_hash", "s"), ("status", "s")),
    "idp_federated": (("provider", "s"), ("subject", "s"), ("user_id", "s")),
    "idp_membership": (("user_id", "s"), ("group_id", "s")),
    "idp_app": (("client_id", "s"), ("kind", "s"), ("secret_hash", "s"), ("redirect_uris", "arr"), ("post_logout_uris", "arr"),
                ("allowed_scopes", "arr"), ("allowed_audiences", "arr"), ("roles", "json"), ("default_roles", "arr")),
    "idp_role_grant": (("subject_type", "s"), ("subject_id", "s"), ("client_id", "s"), ("role", "s")),
    "signing_key": (("kid", "s"), ("alg", "s"), ("public_jwk", "json"), ("status", "s"), ("retire_at", "ts")),
    "oauth_code": (("code_hash", "s"), ("client_id", "s"), ("user_id", "s"), ("redirect_uri", "s"), ("scope", "s"), ("nonce", "s"),
                   ("code_challenge", "s"), ("auth_time", "s"), ("expires_at", "ts")),
    "oauth_refresh": (("token_hash", "s"), ("family_id", "s"), ("client_id", "s"), ("user_id", "s"), ("scope", "s"), ("auth_time", "s"),
                      ("expires_at", "ts"), ("used_at", "ts"), ("revoked_at", "ts")),
    "federation_provider": (("provider", "s"), ("client_id", "s"), ("client_secret_enc", "s"), ("enabled", "bool"), ("mode", "s"),
                            ("allowed_domains", "arr"), ("default_groups", "arr")),
}
PK: dict[str, tuple[str, ...]] = {
    "idp_user": ("id",), "idp_federated": ("provider", "subject"), "idp_membership": ("user_id", "group_id"), "idp_app": ("client_id",),
    "idp_role_grant": ("id",), "signing_key": ("kid",), "oauth_code": ("code_hash",), "oauth_refresh": ("id",), "federation_provider": ("provider",),
}
TABLES = tuple(FIELDS)

tampered = Counter("idp_tampered_rows_total", "Rows refused because their MAC is missing or wrong", ["table"], registry=core.metrics.registry)
_reported: set[tuple] = set()
_reported_lock = threading.Lock()


def _canon(value, kind: str) -> str:
    if value is None:
        return "\x00"                                     # distinct from the empty string
    if kind == "arr":
        return json.dumps(sorted(value))
    if kind == "json":
        return json.dumps(value, sort_keys=True)
    if kind == "ts":
        return str(int(value.timestamp())) if isinstance(value, datetime) else str(int(value))
    if kind == "bool":
        return "1" if value else "0"
    return str(value)


def sign_row(table: str, row: dict) -> str:
    """The MAC for `row` (a dict with at least the MAC'd columns of `table`). Raises VaultLocked when the vault is locked."""
    return core.vault.row_mac(table, *(_canon(row[c], k) for c, k in FIELDS[table]))


def _key(table: str, row: dict) -> tuple:
    return tuple(str(row[c]) for c in PK[table])


def verify_row(table: str, row: dict | None) -> bool:
    """True when the row carries a valid MAC. A missing row, no MAC, a wrong MAC or a locked vault is False (the caller treats it as
    absent). A bad MAC is logged (table and primary key only), counted, and audited once per row per process."""
    if not row:
        return False
    if not core.vault.is_unlocked():
        return False
    try:
        if core.vault.check_row_mac(table, row.get("mac"), *(_canon(row[c], k) for c, k in FIELDS[table])):
            return True
    except Exception:  # noqa: BLE001  (locked mid-call, odd column types: fail closed)
        return False
    key = (table, *_key(table, row))
    tampered.labels(table).inc()
    with _reported_lock:
        first = key not in _reported
        _reported.add(key)
    if first:
        pk = "/".join(key[1:])
        log.warning("row refused, MAC missing or wrong: table=%s key=%s", table, pk)
        try:
            from . import audit
            with core.db.connect(retries=1) as c:
                audit.log(c, "system", "row_mac_invalid", f"{table}:{pk}", table=table)
                c.commit()
        except Exception:  # noqa: BLE001  (auditing must never break a lookup)
            pass
    return False


def valid(table: str, rows: list[dict]) -> list[dict]:
    return [r for r in rows if verify_row(table, r)]


def _where(table: str, pk: tuple) -> tuple[str, tuple]:
    return " AND ".join(f"{c}=%s" for c in PK[table]), pk


def seal(conn, table: str, where: str, params: tuple = ()) -> int:
    """Sign the rows of `table` matching `where`, in the caller's transaction. ONLY for rows this process has just written (or `adopt`):
    it signs whatever the row holds now. Without an open vault the MAC is cleared (the row is ignored until adopted)."""
    rows = conn.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()           # noqa: S608  (table is a constant of this module)
    unlocked = core.vault.is_unlocked()
    for r in rows:
        w, p = _where(table, tuple(r[c] for c in PK[table]))
        conn.execute(f"UPDATE {table} SET mac=%s WHERE {w}", (sign_row(table, r) if unlocked else None, *p))   # noqa: S608
    return len(rows)


def update(conn, table: str, assignments: str, set_params: tuple, where: str, params: tuple = ()) -> int:
    """UPDATE ... SET `assignments` WHERE `where`, then re-sign the rows that carried a valid MAC BEFORE the change (a planted or edited
    row is never legitimised by an unrelated update). Returns the number of rows changed."""
    before = conn.execute(f"SELECT * FROM {table} WHERE {where} FOR UPDATE", params).fetchall()             # noqa: S608
    good = [tuple(r[c] for c in PK[table]) for r in before if verify_row(table, r)]
    n = conn.execute(f"UPDATE {table} SET {assignments} WHERE {where}", (*set_params, *params)).rowcount     # noqa: S608
    for pk in good:
        w, p = _where(table, pk)
        seal(conn, table, w, p)
    return n


def snapshot(conn) -> dict[str, list[tuple]]:
    """Primary keys of every row that verifies now (used around a data-key rotation, which changes every MAC). Includes the kit's own
    web_session and api_token rows (their MACs also change with the data key and the kit does not re-sign them)."""
    out: dict[str, list[tuple]] = {}
    out["web_session"] = [r["token_hash"] for r in conn.execute("SELECT * FROM web_session").fetchall()
                          if core.vault.check_row_mac("web_session", r["mac"], r["token_hash"], r["subject"], r["name"], r["email"],
                                                      json.dumps(sorted(r["roles"])), r["source"], int(r["expires_at"].timestamp()))]
    out["api_token"] = [r["id"] for r in conn.execute("SELECT * FROM api_token WHERE revoked_at IS NULL").fetchall()
                        if core.vault.check_row_mac("api_token", r["mac"], r["id"], r["name"], r["token_hash"], r["prefix"], r["scope"], 0)]
    for t in TABLES:
        out[t] = [tuple(r[c] for c in PK[t]) for r in conn.execute(f"SELECT * FROM {t}").fetchall() if verify_row(t, r)]        # noqa: S608
    return out


def reseal(conn, snap: dict[str, list]) -> int:
    n = 0
    for token_hash in snap.pop("web_session", []):
        r = conn.execute("SELECT * FROM web_session WHERE token_hash=%s", (token_hash,)).fetchone()
        if r:
            conn.execute("UPDATE web_session SET mac=%s WHERE token_hash=%s", (core.local._session_mac(
                r["token_hash"], r["subject"], r["name"], r["email"], r["roles"], r["source"], r["expires_at"]), token_hash))
    for tid in snap.pop("api_token", []):
        r = conn.execute("SELECT * FROM api_token WHERE id=%s", (tid,)).fetchone()
        if r:
            conn.execute("UPDATE api_token SET mac=%s WHERE id=%s", (core.local._token_mac(r["id"], r["name"], r["token_hash"], r["prefix"], r["scope"], False), tid))
    for t, pks in snap.items():
        for pk in pks:
            w, p = _where(t, pk)
            n += seal(conn, t, w, p)
    return n


def adopt(conn) -> dict[str, int]:
    """Sign every row that has no MAC (existing databases). TRUSTS THE DATABASE AS IT IS NOW. Needs the vault open."""
    if not core.vault.is_unlocked():
        raise RuntimeError("adopt needs an open vault")
    return {t: seal(conn, t, "mac IS NULL") for t in TABLES}
