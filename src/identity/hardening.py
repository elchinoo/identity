"""Read-only / AI hardening, applied after every migration (see the kit's `apgkit.masking`).

AgentPG instances have the group role `a1p_readonly` (SELECT on every new public table by default privilege). Direct read-only database
users and AgentPG's restricted MCP server run as members of it. This hook makes the database itself enforce what they can see:

- tables with personal data are replaced for that role by `<table>_masked` views (email, name, username masked);
- tables that hold secrets, hashes or ciphertext and have no view are REVOKEd from the role.

MOST SENSITIVE TABLE OF THE FLEET: `signing_key` (the encrypted private keys that sign every token of every app). A read-only login
must never read it; `tests/test_hardening.py` proves it with a real login role.

Idempotent, and quiet where the role does not exist (plain Postgres). Only the table owner can REVOKE: the result is verified.
"""
from __future__ import annotations

import logging

import psycopg
from apgkit import masking

log = logging.getLogger("identity.hardening")
ROLE = masking.READONLY_ROLE

MASKED_VIEWS = {
    "idp_user": ("idp_user_masked", {"id": "pass", "username": "initial", "email": "email", "name": "initial", "status": "pass",
                                      "created_at": "pass", "last_login_at": "pass"}),            # password_hash is not exposed
    "idp_federated": ("idp_federated_masked", {"provider": "pass", "subject": "hash", "user_id": "pass", "email": "email", "created_at": "pass"}),
    "idp_app": ("idp_app_masked", {"client_id": "pass", "name": "pass", "description": "pass", "kind": "pass", "redirect_uris": "pass",
                                   "post_logout_uris": "pass", "allowed_scopes": "pass", "allowed_audiences": "pass", "roles": "pass",
                                   "default_roles": "pass", "url": "pass", "status": "pass", "created_at": "pass"}),   # secret_hash is not exposed
}
# Secrets, hashes, ciphertext and live credentials, no view: the role gets nothing.
DENIED_TABLES = (
    "signing_key",            # encrypted private signing keys: the most sensitive table of the fleet
    "oauth_code", "oauth_refresh",           # authorization codes and refresh token hashes
    "federation_provider",    # upstream client secret (ciphertext)
    "app_setting",            # kit settings and the vault store (wrapped key, admin password hash)
    "web_session", "api_token", "oidc_login",  # session / API token hashes, PKCE verifiers
)
# Every base table the role must never read, masked or not: `masking.reassert_forever` counts (and closes) grants made after startup.
DENY = tuple(MASKED_VIEWS) + DENIED_TABLES


def apply(conn: psycopg.Connection, role: str = ROLE) -> dict[str, object]:
    """Mask and deny. Returns {"role_exists", "masked": {table: applied}, "denied": {table: bool}}."""
    out: dict[str, object] = {"role_exists": False, "masked": {}, "denied": {}}
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
        log.info("hardening skipped: role %s does not exist", role)
        return out
    out["role_exists"] = True
    for table, (view, columns) in MASKED_VIEWS.items():
        if conn.execute("SELECT to_regclass(%s) AS t", (f"public.{table}",)).fetchone()["t"]:
            out["masked"][table] = masking.mask_view(conn, table, view, columns, role)["applied"]       # type: ignore[index]
    for table in DENIED_TABLES:
        if not conn.execute("SELECT to_regclass(%s) AS t", (f"public.{table}",)).fetchone()["t"]:
            continue
        conn.execute(f'REVOKE SELECT ON public."{table}" FROM "{role}"')
        conn.commit()
        denied = not conn.execute("SELECT has_table_privilege(%s, %s, 'SELECT') AS ok", (role, f"public.{table}")).fetchone()["ok"]
        out["denied"][table] = denied                                                        # type: ignore[index]
        if not denied:
            log.warning("hardening: %s can still read %s (not the owner, or PUBLIC has SELECT)", role, table)
    return out
