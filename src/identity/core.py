"""The shared singletons of this app, built from kit blocks."""
import os
from pathlib import Path

from apgkit import metrics as metrics_mod
from apgkit.auth import AppAuth, Authenticator, LocalAuth
from apgkit.auth.principal import WILDCARD, Principal
from apgkit.config import env_bool, read_secret
from apgkit.db import Database
from apgkit.ratelimit import FailureLimiter
from apgkit.vault import Vault

from . import __version__

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
APP = "identity"
COOKIE_ADMIN, COOKIE_SSO = "idp_admin", "idp_sso"
CSRF_HEADER = "x-identity-csrf"

db = Database()                                              # plain connections, one per request: there is no pool to size
vault = Vault("IDENTITY")
metrics = metrics_mod.Metrics(APP, __version__)


def _db_probe() -> dict[str, float]:
    with db.connect(retries=1) as conn:
        conn.execute("SELECT 1")
    return {"db_up": 1}


metrics.add_insights_collector(lambda: db.connect(retries=1))  # db_insights_* gauges (EDB query statistics), cached; db_insights_available 0 on plain Postgres
metrics.add_db_collector(_db_probe)                          # db_up is 1 when a connection and a trivial query work, else 0
login_limiter = FailureLimiter(window=300, limit=10)        # sign-in failures per client address / per username

# The operator console is governed by one permission set; the local admin password (always available, never federated)
# holds everything. Operator tokens: `read` can look but not change, `metrics` only scrapes. There is no role for a federated
# person: the console never verifies federated tokens, so a role could not be held by anyone.
APP_AUTH = AppAuth(APP, APP, role_permissions={"admin": frozenset({"*"})},
                   scope_permissions={"full": frozenset({"*"}), "read": frozenset({"admin:read"}), "metrics": frozenset({"metrics:scrape"})})
local = LocalAuth(APP_AUTH, env_prefix="IDENTITY", token_prefix="idt_", token_scopes={"read", "metrics", "full"}, vault=vault)

# Static credentials besides IDENTITY_API_KEY (the wildcard admin key), each read from env or <NAME>_FILE on every request and
# compared in constant time by the kit:
#  * IDENTITY_API_KEY_NEXT: a second wildcard admin key, accepted alongside IDENTITY_API_KEY so the admin key can be rotated with no
#    window in which automation is locked out (set NEXT, restart, switch callers, promote NEXT to IDENTITY_API_KEY, drop NEXT).
#  * IDENTITY_DEPLOY_KEY: a narrow credential for deploy tooling. It can read, register and update apps, create groups and make grants
#    (DEPLOY_PERMISSIONS); it cannot reset a client secret, delete anything, create users, rotate keys or touch federation.
DEPLOY_PERMISSIONS = frozenset({"admin:read", "apps:write", "groups:write", "grants:write"})
auth = Authenticator(APP_AUTH, local, db, cookie_name=COOKIE_ADMIN, allow_anonymous=env_bool("IDENTITY_ALLOW_ANONYMOUS"),
                     static_tokens=[(lambda: read_secret("IDENTITY_API_KEY_NEXT"), Principal("static", "static-key-next", frozenset({WILDCARD}), name="api key (next)")),
                                    (lambda: read_secret("IDENTITY_DEPLOY_KEY"), Principal("static", "deploy-key", DEPLOY_PERMISSIONS, name="deploy key"))])


class DatabaseEncodingError(RuntimeError):
    """The database is not UTF-8. On SQL_ASCII, text comes back as bytes and, among other things, the admin password check fails."""


def check_encoding(conn) -> None:
    """Raise DatabaseEncodingError unless the database encoding is UTF8."""
    value = next(iter(conn.execute("SHOW server_encoding").fetchone().values()))
    encoding = value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)
    if encoding.upper() not in {"UTF8", "UTF-8"}:
        raise DatabaseEncodingError(f"the database encoding is {encoding}, but Identity needs UTF8 (with {encoding} text comes back as bytes "
                                    "and sign-in fails with 'invalid credentials'). Create the database with ENCODING 'UTF8' "
                                    "(CREATE DATABASE identity ENCODING 'UTF8' TEMPLATE template0) and point DATABASE_URL at it.")


def issuer(public_url: str) -> str:
    return (os.environ.get("IDENTITY_ISSUER") or public_url).rstrip("/")


MAX_NEXT = 2048


def safe_next(value: str | None) -> str:
    """Where to go after signing in: only a same-site path. Longer than the kit's default, because the authorization URL an app
    sends the browser to (client id, a long redirect URI, state, nonce, PKCE challenge) easily passes 300 characters."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and len(value) <= MAX_NEXT:
        return value
    return "/"
