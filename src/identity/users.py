"""People, groups and who holds which role in which app."""
import re

import psycopg
from apgkit import passwords

from .ids import new_user_id

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
GROUP = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$")
_DUMMY = passwords.hash_password("not-a-real-password-used-for-timing")


class UserError(ValueError):
    pass


class NotFound(UserError):
    pass


def _clean_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL.match(email):
        raise UserError("the e-mail address is not valid")
    return email


def create_user(conn, *, username: str, email: str, name: str = "", password: str | None = None, groups: list[str] | None = None) -> dict:
    username = (username or "").strip().lower()
    if not USERNAME.match(username):
        raise UserError("username must be 2-64 lowercase letters, digits, dots, dashes or underscores")
    email = _clean_email(email)
    name = (name or "").strip()
    if len(name) > 120 or any(ord(c) < 32 for c in name):
        raise UserError("name is too long or has control characters")
    pw_hash = None
    if password:
        try:
            passwords.check_strength(password)
        except ValueError as exc:
            raise UserError(str(exc)) from exc
        pw_hash = passwords.hash_password(password)
    uid = new_user_id()
    try:
        conn.execute("INSERT INTO idp_user (id, username, email, name, password_hash) VALUES (%s,%s,%s,%s,%s)", (uid, username, email, name, pw_hash))
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise UserError("that username or e-mail address is already in use") from exc
    for g in groups or []:
        add_to_group(conn, uid, g)
    conn.commit()
    return get(conn, uid)


def get(conn, user_id: str) -> dict:
    row = conn.execute("SELECT id, username, email, name, status, (password_hash IS NOT NULL) AS has_password, created_at, last_login_at "
                       "FROM idp_user WHERE id=%s", (user_id,)).fetchone()
    if not row:
        raise NotFound("no such user")
    row["groups"] = [r["name"] for r in conn.execute(
        "SELECT g.name FROM idp_group g JOIN idp_membership m ON m.group_id=g.id WHERE m.user_id=%s ORDER BY g.name", (user_id,))]
    return row


def listing(conn, query: str | None = None, limit: int = 200) -> list[dict]:
    if query:
        like = "%" + re.sub(r"([\\%_])", r"\\\1", query) + "%"
        rows = conn.execute("SELECT id FROM idp_user WHERE username ILIKE %s OR email ILIKE %s OR name ILIKE %s ORDER BY username LIMIT %s",
                            (like, like, like, limit)).fetchall()
    else:
        rows = conn.execute("SELECT id FROM idp_user ORDER BY username LIMIT %s", (limit,)).fetchall()
    return [get(conn, r["id"]) for r in rows]


def update(conn, user_id: str, *, name: str | None = None, email: str | None = None, status: str | None = None) -> dict:
    cur = get(conn, user_id)
    if status is not None and status not in {"active", "disabled"}:
        raise UserError("status must be active or disabled")
    try:
        conn.execute("UPDATE idp_user SET name=%s, email=%s, status=%s WHERE id=%s",
                     ((name if name is not None else cur["name"]).strip()[:120], _clean_email(email) if email else cur["email"],
                      status or cur["status"], user_id))
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise UserError("another user already has that e-mail address") from exc
    if status == "disabled":                               # a disabled person's refresh tokens stop working at once
        conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE user_id=%s AND revoked_at IS NULL", (user_id,))
    conn.commit()
    return get(conn, user_id)


def set_password(conn, user_id: str, password: str) -> None:
    get(conn, user_id)
    try:
        passwords.check_strength(password)
    except ValueError as exc:
        raise UserError(str(exc)) from exc
    conn.execute("UPDATE idp_user SET password_hash=%s WHERE id=%s", (passwords.hash_password(password), user_id))
    conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE user_id=%s AND revoked_at IS NULL", (user_id,))
    conn.commit()


def authenticate(conn, login: str, password: str) -> dict | None:
    """The user for a username-or-e-mail and password, or None. Takes the same time whether or not the user exists."""
    login = (login or "").strip().lower()
    row = conn.execute("SELECT id, password_hash, status FROM idp_user WHERE username=%s OR lower(email)=%s ORDER BY (username=%s) DESC LIMIT 1",
                       (login, login, login)).fetchone()
    ok = passwords.verify_password(password or "", row["password_hash"] if row and row["password_hash"] else _DUMMY)
    if not row or not row["password_hash"] or not ok or row["status"] != "active":
        return None
    conn.execute("UPDATE idp_user SET last_login_at = now() WHERE id=%s", (row["id"],))
    conn.commit()
    return get(conn, row["id"])


def delete(conn, user_id: str) -> None:
    get(conn, user_id)
    conn.execute("DELETE FROM idp_role_grant WHERE subject_type='user' AND subject_id=%s", (user_id,))
    conn.execute("DELETE FROM idp_user WHERE id=%s", (user_id,))
    conn.commit()


# ---- groups -----------------------------------------------------------------------------------------------------------
def create_group(conn, name: str, description: str = "") -> dict:
    name = (name or "").strip().lower()
    if not GROUP.match(name):
        raise UserError("group name must be lowercase letters, digits, dots, dashes or underscores")
    try:
        row = conn.execute("INSERT INTO idp_group (name, description) VALUES (%s,%s) RETURNING id, name, description", (name, description[:200])).fetchone()
    except psycopg.errors.UniqueViolation as exc:
        conn.rollback()
        raise UserError("a group with that name already exists") from exc
    conn.commit()
    return row


def groups(conn) -> list[dict]:
    return conn.execute("SELECT g.id, g.name, g.description, (SELECT count(*) FROM idp_membership m WHERE m.group_id=g.id) AS members "
                        "FROM idp_group g ORDER BY g.name").fetchall()


def _group_id(conn, name: str) -> int:
    row = conn.execute("SELECT id FROM idp_group WHERE name=%s", (name,)).fetchone()
    if not row:
        raise NotFound(f"no such group: {name}")
    return row["id"]


def delete_group(conn, name: str) -> None:
    gid = _group_id(conn, name)
    conn.execute("DELETE FROM idp_role_grant WHERE subject_type='group' AND subject_id=%s", (str(gid),))
    conn.execute("DELETE FROM idp_group WHERE id=%s", (gid,))
    conn.commit()


def add_to_group(conn, user_id: str, group: str) -> None:
    conn.execute("INSERT INTO idp_membership (user_id, group_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (user_id, _group_id(conn, group)))


def remove_from_group(conn, user_id: str, group: str) -> None:
    conn.execute("DELETE FROM idp_membership WHERE user_id=%s AND group_id=%s", (user_id, _group_id(conn, group)))
    conn.commit()


# ---- role grants -------------------------------------------------------------------------------------------------------
def grant_role(conn, subject_type: str, subject: str, client_id: str, role: str) -> None:
    """`subject` is a user id or a group NAME. The role must be one the app defines."""
    app = conn.execute("SELECT roles FROM idp_app WHERE client_id=%s", (client_id,)).fetchone()
    if not app:
        raise NotFound("no such app")
    if role not in {r["name"] for r in app["roles"]}:
        raise UserError(f"{client_id} does not define a role called {role!r}")
    if subject_type == "user":
        get(conn, subject)
        sid = subject
    elif subject_type == "group":
        sid = str(_group_id(conn, subject))
    else:
        raise UserError("subject_type must be user or group")
    conn.execute("INSERT INTO idp_role_grant (subject_type, subject_id, client_id, role) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                 (subject_type, sid, client_id, role))
    conn.commit()


def revoke_role(conn, grant_id: int) -> bool:
    row = conn.execute("DELETE FROM idp_role_grant WHERE id=%s RETURNING id", (grant_id,)).fetchone()
    conn.commit()
    return row is not None


def grants(conn, client_id: str | None = None) -> list[dict]:
    rows = conn.execute("SELECT r.id, r.subject_type, r.subject_id, r.client_id, r.role, r.created_at, "
                        "CASE r.subject_type WHEN 'user' THEN (SELECT username FROM idp_user WHERE id=r.subject_id) "
                        "ELSE (SELECT name FROM idp_group WHERE id::text=r.subject_id) END AS subject_name "
                        "FROM idp_role_grant r WHERE (%s::text IS NULL OR r.client_id=%s) ORDER BY r.client_id, r.role, r.id", (client_id, client_id)).fetchall()
    return rows


def roles_for(conn, user_id: str, client_id: str) -> list[str]:
    """The roles a user holds in one app, namespaced `<client_id>:<role>`: direct grants, group grants and the app's default roles."""
    rows = conn.execute(
        "SELECT role FROM idp_role_grant WHERE client_id=%s AND ((subject_type='user' AND subject_id=%s) OR (subject_type='group' AND subject_id IN "
        "(SELECT group_id::text FROM idp_membership WHERE user_id=%s))) UNION SELECT unnest(default_roles) FROM idp_app WHERE client_id=%s",
        (client_id, user_id, user_id, client_id)).fetchall()
    return sorted(f"{client_id}:{r['role']}" for r in rows)
