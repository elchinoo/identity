"""Sign in with an upstream provider (Google over OpenID Connect, GitHub over OAuth 2.0), then map the person to a local user.

Mapping rules, strictest first:
  1. An identity already linked (provider + subject) signs in as its user.
  2. A VERIFIED e-mail address that matches an existing user links to that user. An unverified e-mail never links.
  3. Otherwise, only in `open` mode and only for e-mail domains the admin listed, a new passwordless user is created
     and put in the provider's default groups.
  4. Otherwise: refused. The default mode is `invite_only`: an administrator creates the user first.
A disabled user is refused whatever the provider says.
"""
import re
import secrets
from collections.abc import Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from apgkit.auth.oidc import TokenError, _client_factory
from apgkit.auth.rp import RelyingParty
from psycopg.types.json import Jsonb  # noqa: F401  (kept for providers that later store raw profiles)

from . import core, users
from .ids import new_user_id

GOOGLE_ISSUER = "https://accounts.google.com"
GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"
PROVIDERS = {"google": "Google", "github": "GitHub"}
STATE_MINUTES = 10

http_factory: Callable[[], httpx.Client] = _client_factory       # tests replace this


class FederationError(Exception):
    """The upstream sign-in did not complete. The message is safe to show to the person."""


def list_providers(conn) -> list[dict]:
    return conn.execute("SELECT provider, client_id, enabled, mode, allowed_domains, default_groups FROM federation_provider ORDER BY provider").fetchall()


def enabled(conn) -> list[dict]:
    return [{"provider": r["provider"], "label": PROVIDERS[r["provider"]]} for r in list_providers(conn) if r["enabled"]]


def upsert_provider(conn, provider: str, client_id: str, client_secret: str | None, *, enabled: bool = True, mode: str = "invite_only",
                    allowed_domains: list[str] | None = None, default_groups: list[str] | None = None) -> dict:
    if provider not in PROVIDERS:
        raise FederationError("provider must be google or github")
    if mode not in {"invite_only", "open"}:
        raise FederationError("mode must be invite_only or open")
    domains = [d.strip().lower() for d in (allowed_domains or []) if d.strip()]
    if any(not re.fullmatch(r"[a-z0-9.-]{3,100}", d) for d in domains):
        raise FederationError("allowed_domains must be plain domain names")
    if mode == "open" and not domains:
        raise FederationError("open mode needs at least one allowed e-mail domain")
    groups = [g for g in (default_groups or [])]
    for g in groups:
        if not conn.execute("SELECT 1 FROM idp_group WHERE name=%s", (g,)).fetchone():
            raise FederationError(f"no such group: {g}")
    if not client_id.strip():
        raise FederationError("client id is required")
    existing = conn.execute("SELECT client_secret_enc FROM federation_provider WHERE provider=%s", (provider,)).fetchone()
    if client_secret:
        if not core.vault.is_initialized(conn):
            raise FederationError("set an admin password first: the provider secret is stored encrypted under it")
        enc = core.vault.encrypt(client_secret.strip())
    elif existing:
        enc = existing["client_secret_enc"]
    else:
        raise FederationError("the client secret is required the first time")
    conn.execute(
        "INSERT INTO federation_provider (provider, client_id, client_secret_enc, enabled, mode, allowed_domains, default_groups) VALUES (%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (provider) DO UPDATE SET client_id=EXCLUDED.client_id, client_secret_enc=EXCLUDED.client_secret_enc, enabled=EXCLUDED.enabled, "
        "mode=EXCLUDED.mode, allowed_domains=EXCLUDED.allowed_domains, default_groups=EXCLUDED.default_groups",
        (provider, client_id.strip(), enc, enabled, mode, domains, groups))
    conn.commit()
    return next(p for p in list_providers(conn) if p["provider"] == provider)


def delete_provider(conn, provider: str) -> None:
    conn.execute("DELETE FROM federation_provider WHERE provider=%s", (provider,))
    conn.execute("DELETE FROM idp_federated WHERE provider=%s", (provider,))
    conn.commit()


def _config(conn, provider: str) -> dict:
    row = conn.execute("SELECT * FROM federation_provider WHERE provider=%s AND enabled", (provider,)).fetchone()
    if not row:
        raise FederationError("that sign-in method is not enabled")
    return row


def _callback(base_url: str, provider: str) -> str:
    return f"{base_url}/login/{provider}/callback"


def begin(conn, provider: str, base_url: str, next_url: str | None) -> str:
    cfg = _config(conn, provider)
    redirect_uri = _callback(base_url, provider)
    if provider == "google":
        rp = RelyingParty(GOOGLE_ISSUER, cfg["client_id"], lambda: core.vault.decrypt(cfg["client_secret_enc"]), http=http_factory, scopes="openid email profile")
        url = rp.begin(conn, redirect_uri, next_url)
        state = parse_qs(urlsplit(url).query)["state"][0]
        conn.execute("UPDATE oidc_login SET return_to=%s WHERE state=%s", (core.safe_next(next_url), state))   # the kit keeps only 300 characters
        conn.commit()
        return url
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    import base64
    import hashlib
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    conn.execute("DELETE FROM oidc_login WHERE created_at < now() - %s * interval '1 minute'", (STATE_MINUTES,))
    conn.execute("INSERT INTO oidc_login (state, verifier, nonce, return_to) VALUES (%s,%s,'-',%s)", (state, verifier, core.safe_next(next_url)))
    conn.commit()
    return f"{GITHUB_AUTHORIZE}?" + urlencode({"client_id": cfg["client_id"], "redirect_uri": redirect_uri, "scope": "read:user user:email",
                                              "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})


def _github_identity(conn, cfg: dict, redirect_uri: str, code: str, state: str) -> tuple[dict, str]:
    row = conn.execute("DELETE FROM oidc_login WHERE state=%s AND created_at > now() - %s * interval '1 minute' RETURNING verifier, return_to",
                       (state, STATE_MINUTES)).fetchone()
    conn.commit()
    if not row:
        raise FederationError("the sign-in attempt is unknown or expired; start again")
    with http_factory() as c:
        r = c.post(GITHUB_TOKEN, data={"client_id": cfg["client_id"], "client_secret": core.vault.decrypt(cfg["client_secret_enc"]), "code": code,
                                       "redirect_uri": redirect_uri, "code_verifier": row["verifier"]}, headers={"Accept": "application/json"})
        token = r.json().get("access_token") if r.status_code == 200 else None
        if not token:
            raise FederationError("GitHub refused the sign-in")
        h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        profile = c.get(f"{GITHUB_API}/user", headers=h)
        emails = c.get(f"{GITHUB_API}/user/emails", headers=h)
    if profile.status_code != 200 or emails.status_code != 200:
        raise FederationError("could not read your GitHub profile")
    primary = next((e for e in emails.json() if e.get("primary") and e.get("verified")), None)
    p = profile.json()
    return {"sub": str(p["id"]), "email": (primary or {}).get("email", ""), "email_verified": bool(primary),
            "name": p.get("name") or p.get("login") or ""}, row["return_to"]


def finish(conn, provider: str, base_url: str, code: str, state: str) -> tuple[dict, str]:
    """Complete an upstream sign-in. Returns (local user, return_to). Raises FederationError."""
    cfg = _config(conn, provider)
    redirect_uri = _callback(base_url, provider)
    try:
        if provider == "google":
            rp = RelyingParty(GOOGLE_ISSUER, cfg["client_id"], lambda: core.vault.decrypt(cfg["client_secret_enc"]), http=http_factory, scopes="openid email profile")
            claims, back, _ = rp.finish(conn, redirect_uri, code, state)
        else:
            claims, back = _github_identity(conn, cfg, redirect_uri, code, state)
    except TokenError as exc:
        raise FederationError(str(exc)) from exc
    user = resolve(conn, cfg, provider, claims)
    return user, back


def resolve(conn, cfg: dict, provider: str, claims: dict) -> dict:
    subject, email = str(claims["sub"]), (claims.get("email") or "").strip().lower()
    verified = bool(claims.get("email_verified"))
    linked = conn.execute("SELECT user_id FROM idp_federated WHERE provider=%s AND subject=%s", (provider, subject)).fetchone()
    user_id = linked["user_id"] if linked else None
    if user_id is None and email and verified:
        match = conn.execute("SELECT id FROM idp_user WHERE lower(email)=%s", (email,)).fetchone()
        if match:
            user_id = match["id"]
    if user_id is None and email and verified and cfg["mode"] == "open" and email.rsplit("@", 1)[-1] in cfg["allowed_domains"]:
        base = re.sub(r"[^a-z0-9._-]", "", email.split("@")[0]) or "user"
        username, n = base[:60], 1
        while conn.execute("SELECT 1 FROM idp_user WHERE username=%s", (username,)).fetchone() or len(username) < 2:
            n += 1
            username = f"{base[:55]}{n}"
        user_id = new_user_id()
        conn.execute("INSERT INTO idp_user (id, username, email, name) VALUES (%s,%s,%s,%s)", (user_id, username, email, str(claims.get("name") or "")[:120]))
        for g in cfg["default_groups"]:
            users.add_to_group(conn, user_id, g)
    if user_id is None:
        raise FederationError("there is no account for this identity here. Ask an administrator to create one for your e-mail address.")
    row = conn.execute("SELECT id, status FROM idp_user WHERE id=%s", (user_id,)).fetchone()
    if not row or row["status"] != "active":
        raise FederationError("this account is disabled")
    conn.execute("INSERT INTO idp_federated (provider, subject, user_id, email) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING", (provider, subject, user_id, email))
    conn.execute("UPDATE idp_user SET last_login_at = now() WHERE id=%s", (user_id,))
    conn.commit()
    return users.get(conn, user_id)
