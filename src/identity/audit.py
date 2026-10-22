"""Who changed what. Written in the same transaction as the change."""
from psycopg.types.json import Jsonb


def log(conn, actor: str, action: str, target: str = "", **detail) -> None:
    conn.execute("INSERT INTO idp_audit (actor, action, target, detail) VALUES (%s,%s,%s,%s)", (actor[:60], action, target[:120], Jsonb(detail)))


def recent(conn, limit: int = 200) -> list[dict]:
    return conn.execute("SELECT id, at, actor, action, target, detail FROM idp_audit ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
