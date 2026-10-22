import argparse
import os
import sys

from apgkit import migrate as kit_migrate
from apgkit.auth.schema import SQL as AUTH_SQL

from . import core


def run_migrations() -> list[str]:
    with core.db.connect() as conn:
        conn.execute(AUTH_SQL)
        conn.commit()
    return kit_migrate.run(core.db, core.MIGRATIONS, table="identity_migrations")


def _serve() -> None:
    import uvicorn

    uvicorn.run("identity.api:app", host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")),
                proxy_headers=True, forwarded_allow_ips="*")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="identity")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply SQL migrations")
    sub.add_parser("serve", help="run the identity provider")
    sub.add_parser("start", help="container entrypoint: migrate, then serve")
    sub.add_parser("reset-admin", help="forget the admin password and vault (recovery)")
    args = p.parse_args(argv)
    if args.cmd == "migrate":
        applied = run_migrations()
        print("applied:", ", ".join(applied) if applied else "nothing (up to date)")
    elif args.cmd == "serve":
        _serve()
    elif args.cmd == "start":
        try:
            applied = run_migrations()
        except Exception as exc:  # noqa: BLE001
            print(f"startup failed while migrating: {exc}\nCheck that the database is reachable. If it mentions an extension, "
                  "enable it first: agentpg extensions create <instance-id> pgcrypto", file=sys.stderr)
            return 1
        print("migrations applied:", ", ".join(applied) if applied else "none (up to date)")
        _serve()
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
