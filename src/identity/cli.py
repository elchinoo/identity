import argparse
import os
import sys

from apgkit import migrate as kit_migrate
from apgkit.auth.schema import SQL as AUTH_SQL

from . import audit, core, hardening, keys


def run_migrations() -> list[str]:
    with core.db.connect() as conn:
        core.check_encoding(conn)                    # before anything is created in a database Identity cannot use
        conn.execute(AUTH_SQL)
        conn.commit()
    return kit_migrate.run(core.db, core.MIGRATIONS, table="identity_migrations", after_migrate=[hardening.apply])


def forwarded_allow_ips() -> str:
    """Peers whose X-Forwarded-* headers are believed (comma-separated addresses or networks). Default: loopback only, so a caller cannot
    choose the address the login limiter sees. Behind a reverse proxy, set IDENTITY_FORWARDED_ALLOW_IPS to that proxy's address
    (AgentPG puts a single proxy in front of the app; use its address, never '*')."""
    return os.environ.get("IDENTITY_FORWARDED_ALLOW_IPS", "").strip() or "127.0.0.1"


def _serve() -> None:
    import uvicorn

    uvicorn.run("identity.api:app", host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")),
                proxy_headers=True, forwarded_allow_ips=forwarded_allow_ips())


def _rotate_keys(args) -> int:
    """Needs the vault unlocked, which for the CLI means IDENTITY_ENCRYPTION_KEY (or its _FILE) is set in this process's environment."""
    if args.emergency and not args.yes:
        print("refusing: --emergency removes every old signing key at once and signs everyone out; add --yes to proceed", file=sys.stderr)
        return 2
    with core.db.connect() as conn:
        core.vault.try_unlock_with_platform_secret(conn)
        if not core.vault.is_unlocked():
            print("the vault is locked: set IDENTITY_ENCRYPTION_KEY (or IDENTITY_ENCRYPTION_KEY_FILE) for this command", file=sys.stderr)
            return 1
        if args.emergency:
            out = keys.emergency_rotate(conn, "cli", args.reason)
            print(f"emergency rotation done: new key {out['kid']}; removed {len(out['removed_keys'])} key(s), revoked {out['refresh_tokens_revoked']} "
                  f"refresh token(s), ended {out['sso_sessions_ended']} SSO session(s). Apps stop accepting old tokens once their JWKS cache "
                  "refreshes (5 minutes by default); other identity replicas notice within 30 seconds.")
        else:
            kid = keys.rotate(conn)
            audit.log(conn, "cli", "signing_key_rotated", kid)
            conn.commit()
            print(f"rotated: new key {kid}; the old key stays published for 24 hours")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="identity")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply SQL migrations")
    sub.add_parser("serve", help="run the identity provider")
    sub.add_parser("start", help="container entrypoint: migrate, then serve")
    rk = sub.add_parser("rotate-keys", help="rotate the signing key: graceful by default (the old key stays published 24 h); --emergency hard-revokes")
    rk.add_argument("--emergency", action="store_true", help="remove every old key from the JWKS at once, revoke all refresh tokens, end SSO sessions")
    rk.add_argument("--yes", action="store_true", help="required with --emergency")
    rk.add_argument("--reason", default="", help="recorded in the audit log")
    sub.add_parser("reset-admin", help="forget the admin password and vault (recovery)")
    args = p.parse_args(argv)
    if args.cmd == "migrate":
        try:
            applied = run_migrations()
        except core.DatabaseEncodingError as exc:
            print(f"migrate failed: {exc}", file=sys.stderr)
            return 1
        print("applied:", ", ".join(applied) if applied else "nothing (up to date)")
    elif args.cmd == "serve":
        _serve()
    elif args.cmd == "start":
        try:
            applied = run_migrations()
        except core.DatabaseEncodingError as exc:
            print(f"startup failed: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"startup failed while migrating: {exc}\nCheck that the database is reachable. If it mentions an extension, "
                  "enable it first: agentpg extensions create <instance-id> pgcrypto", file=sys.stderr)
            return 1
        print("migrations applied:", ", ".join(applied) if applied else "none (up to date)")
        _serve()
    elif args.cmd == "rotate-keys":
        return _rotate_keys(args)
    elif args.cmd == "reset-admin":
        with core.db.connect() as conn:
            core.local.reset_admin(conn)
            conn.execute("DELETE FROM signing_key")
            conn.execute("UPDATE federation_provider SET enabled=false")
            conn.commit()
        print("admin password and vault cleared, signing keys and federation secrets discarded; the setup code flow is active again")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
