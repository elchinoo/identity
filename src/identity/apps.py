"""Applications registered with the ecosystem: OAuth clients with their redirect URIs, scopes, roles and secrets."""
import re
import secrets
from urllib.parse import urlsplit

import psycopg
from apgkit.ids import sha256
from psycopg.types.json import Jsonb

CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")
ROLE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,59}$")
KINDS = {"web", "public", "service"}
STANDARD_SCOPES = ("openid", "profile", "email", "roles", "offline_access")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class AppError(ValueError):
    pass


class NotFound(AppError):
    pass


def check_redirect(uri: str) -> str:
    """Exact URIs only: https, or http for a loopback host; no wildcards, no fragment, no credentials."""
    u = urlsplit(uri)
    host = u.hostname or ""
    if not uri or len(uri) > 300 or u.scheme not in {"https", "http"} or not host or u.fragment or u.username or u.password or "*" in uri:
        raise AppError(f"{uri!r} is not an acceptable redirect URI (an exact https URL, or http on localhost; no wildcard or fragment)")
    if u.scheme == "http" and host not in LOOPBACK and not host.endswith(".localhost"):
        raise AppError(f"{uri!r} must use https (plain http is only accepted for localhost)")
    return uri


def _list(values, what: str, pattern: re.Pattern | None = None, limit: int = 50) -> list[str]:
    if not isinstance(values, list) or len(values) > limit or any(not isinstance(v, str) for v in values):
        raise AppError(f"{what} must be a list of at most {limit} texts")
    if pattern and any(not pattern.match(v) for v in values):
        raise AppError(f"{what} has an entry in the wrong format")
    return list(dict.fromkeys(values))


def clean(spec: dict, kind: str) -> dict:
    roles = spec.get("roles", [])
    if not isinstance(roles, list) or len(roles) > 40 or any(not isinstance(r, dict) or not ROLE.match(str(r.get("name", ""))) for r in roles):
        raise AppError("roles must be a list of {name, description}")
    roles = [{"name": r["name"], "description": str(r.get("description", ""))[:200]} for r in roles]
    names = {r["name"] for r in roles}
    default = _list(spec.get("default_roles", []), "default_roles", ROLE)
    if set(default) - names:
        raise AppError("default_roles must be roles the app defines")
    redirects = [check_redirect(u) for u in _list(spec.get("redirect_uris", []), "redirect_uris", limit=20)]
    if kind in {"web", "public"} and not redirects:
        raise AppError("a web or public app needs at least one redirect URI")
    return {"redirect_uris": redirects,
            "post_logout_uris": [check_redirect(u) for u in _list(spec.get("post_logout_uris", []), "post_logout_uris", limit=20)],
            "allowed_scopes": _list(spec.get("allowed_scopes", []), "allowed_scopes", SCOPE),
            "allowed_audiences": _list(spec.get("allowed_audiences", []), "allowed_audiences", CLIENT_ID),
            "roles": roles, "default_roles": default, "url": str(spec.get("url", ""))[:300]}


def register(conn, client_id: str, name: str, kind: str, spec: dict) -> tuple[dict, str | None]:
    """Create an app. Returns (app, secret); the secret is shown once and only its hash is stored (none for public clients)."""
    if not CLIENT_ID.match(client_id or ""):
        raise AppError("client id must be 2-40 lowercase letters, digits or dashes")
    if kind not in KINDS:
        raise AppError("kind must be web, public or service")
    if not 1 <= len((name or "").strip()) <= 80:
        raise AppError("name must be 1 to 80 characters")
    c = clean(spec, kind)
    secret = None if kind == "public" else "cs_" + secrets.token_urlsafe(32)
    try:
        conn.execute(
            "INSERT INTO idp_app (client_id, name, description, kind, secret_hash, redirect_uris, post_logout_uris, allowed_scopes, "
            "allowed_audiences, roles, default_roles, url) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (client_id, name.strip(), str(spec.get("description", ""))[:300], kind, sha256(secret) if secret else None, c["redirect_uris"],
             c["post_logout_uris"], c["allowed_scopes"], c["allowed_audiences"], Jsonb(c["roles"]), c["default_roles"], c["url"]))
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise AppError("an app with that client id already exists") from exc
    conn.commit()
    return get(conn, client_id), secret


def get(conn, client_id: str) -> dict:
    row = conn.execute("SELECT client_id, name, description, kind, redirect_uris, post_logout_uris, allowed_scopes, allowed_audiences, roles, "
                       "default_roles, url, status, created_at FROM idp_app WHERE client_id=%s", (client_id,)).fetchone()
    if not row:
        raise NotFound("no such app")
    return row


def listing(conn) -> list[dict]:
    return conn.execute("SELECT client_id, name, kind, url, status, jsonb_array_length(roles) AS roles, "
                        "(SELECT count(*) FROM idp_role_grant g WHERE g.client_id=a.client_id) AS grants FROM idp_app a ORDER BY name").fetchall()


def update(conn, client_id: str, spec: dict) -> dict:
    cur = get(conn, client_id)
    merged = {**{k: cur[k] for k in ("redirect_uris", "post_logout_uris", "allowed_scopes", "allowed_audiences", "roles", "default_roles", "url")},
              **{k: v for k, v in spec.items() if k in {"redirect_uris", "post_logout_uris", "allowed_scopes", "allowed_audiences", "roles", "default_roles", "url"}}}
    c = clean(merged, cur["kind"])
    status = spec.get("status", cur["status"])
    if status not in {"active", "disabled"}:
        raise AppError("status must be active or disabled")
    conn.execute("UPDATE idp_app SET name=%s, description=%s, redirect_uris=%s, post_logout_uris=%s, allowed_scopes=%s, allowed_audiences=%s, "
                 "roles=%s, default_roles=%s, url=%s, status=%s WHERE client_id=%s",
                 (str(spec.get("name", cur["name"]))[:80], str(spec.get("description", cur["description"]))[:300], c["redirect_uris"],
                  c["post_logout_uris"], c["allowed_scopes"], c["allowed_audiences"], Jsonb(c["roles"]), c["default_roles"], c["url"], status, client_id))
    # a role removed from the catalog loses its grants
    conn.execute("DELETE FROM idp_role_grant WHERE client_id=%s AND NOT (role = ANY(%s))", (client_id, [r["name"] for r in c["roles"]]))
    if status == "disabled":
        conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE client_id=%s AND revoked_at IS NULL", (client_id,))
    conn.commit()
    return get(conn, client_id)


def rotate_secret(conn, client_id: str) -> str:
    app = get(conn, client_id)
    if app["kind"] == "public":
        raise AppError("a public client has no secret")
    secret = "cs_" + secrets.token_urlsafe(32)
    conn.execute("UPDATE idp_app SET secret_hash=%s WHERE client_id=%s", (sha256(secret), client_id))
    conn.commit()
    return secret


def delete(conn, client_id: str) -> None:
    get(conn, client_id)
    conn.execute("DELETE FROM idp_app WHERE client_id=%s", (client_id,))
    conn.commit()
