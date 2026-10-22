"""The shared singletons of this app, built from kit blocks."""
import os
from pathlib import Path

from apgkit import metrics as metrics_mod
from apgkit.auth import AppAuth, Authenticator, LocalAuth
from apgkit.config import env_bool
from apgkit.db import Database
from apgkit.netguard import NetGuard
from apgkit.ratelimit import FailureLimiter
from apgkit.vault import Vault

from . import __version__

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
APP = "identity"
COOKIE_ADMIN, COOKIE_SSO = "idp_admin", "idp_sso"
CSRF_HEADER = "x-identity-csrf"

db = Database(pool_max=int(os.environ.get("IDENTITY_POOL_MAX", "20")))
vault = Vault("IDENTITY")
netguard = NetGuard("IDENTITY_ALLOW_PRIVATE_URLS")
metrics = metrics_mod.Metrics(APP, __version__)
login_limiter = FailureLimiter(window=300, limit=10)        # sign-in failures per client address / per username

# The operator console is governed by one permission set; the local admin password (always available, never federated)
# holds everything. Operator tokens: `read` can look but not change, `metrics` only scrapes.
APP_AUTH = AppAuth(APP, APP, role_permissions={"admin": frozenset({"*"}), "auditor": frozenset({"admin:read"})},
                   scope_permissions={"full": frozenset({"*"}), "read": frozenset({"admin:read"}), "metrics": frozenset({"metrics:scrape"})})
local = LocalAuth(APP_AUTH, env_prefix="IDENTITY", token_prefix="idt_", token_scopes={"read", "metrics", "full"}, vault=vault)
auth = Authenticator(APP_AUTH, local, db, cookie_name=COOKIE_ADMIN, allow_anonymous=env_bool("IDENTITY_ALLOW_ANONYMOUS"))


def issuer(public_url: str) -> str:
    return (os.environ.get("IDENTITY_ISSUER") or public_url).rstrip("/")


MAX_NEXT = 2048


def safe_next(value: str | None) -> str:
    """Where to go after signing in: only a same-site path. Longer than the kit's default, because the authorization URL an app
    sends the browser to (client id, a long redirect URI, state, nonce, PKCE challenge) easily passes 300 characters."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and len(value) <= MAX_NEXT:
        return value
    return "/"
