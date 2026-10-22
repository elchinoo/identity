"""The operator console API: users, groups, apps, role grants, signing keys, federation providers and the audit trail."""
import contextlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import apps, audit, core, federation, keys, users
from .core import db, vault


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserBody(_Body):
    username: str = Field(max_length=64)
    email: str = Field(max_length=254)
    name: str = Field("", max_length=120)
    password: str | None = Field(None, max_length=256)
    groups: list[str] = Field(default_factory=list, max_length=50)


class UserPatch(_Body):
    name: str | None = Field(None, max_length=120)
    email: str | None = Field(None, max_length=254)
    status: str | None = Field(None, max_length=10)


class PasswordBody(_Body):
    password: str = Field(max_length=256)


class GroupBody(_Body):
    name: str = Field(max_length=63)
    description: str = Field("", max_length=200)


class MemberBody(_Body):
    group: str = Field(max_length=63)


class AppBody(_Body):
    client_id: str = Field(max_length=40)
    name: str = Field(max_length=80)
    kind: str = Field(pattern="^(web|public|service)$")
    description: str = Field("", max_length=300)
    redirect_uris: list[str] = Field(default_factory=list, max_length=20)
    post_logout_uris: list[str] = Field(default_factory=list, max_length=20)
    allowed_scopes: list[str] = Field(default_factory=list, max_length=50)
    allowed_audiences: list[str] = Field(default_factory=list, max_length=50)
    roles: list[dict] = Field(default_factory=list, max_length=40)
    default_roles: list[str] = Field(default_factory=list, max_length=40)
    url: str = Field("", max_length=300)


class AppPatch(_Body):
    name: str | None = Field(None, max_length=80)
    description: str | None = Field(None, max_length=300)
    redirect_uris: list[str] | None = Field(None, max_length=20)
    post_logout_uris: list[str] | None = Field(None, max_length=20)
    allowed_scopes: list[str] | None = Field(None, max_length=50)
    allowed_audiences: list[str] | None = Field(None, max_length=50)
    roles: list[dict] | None = Field(None, max_length=40)
    default_roles: list[str] | None = Field(None, max_length=40)
    url: str | None = Field(None, max_length=300)
    status: str | None = Field(None, max_length=10)


class GrantBody(_Body):
    subject_type: str = Field(pattern="^(user|group)$")
    subject: str = Field(max_length=100)
    client_id: str = Field(max_length=40)
    role: str = Field(max_length=40)


class ProviderBody(_Body):
    client_id: str = Field(max_length=300)
    client_secret: str | None = Field(None, max_length=500)
    enabled: bool = True
    mode: str = Field("invite_only", pattern="^(invite_only|open)$")
    allowed_domains: list[str] = Field(default_factory=list, max_length=20)
    default_groups: list[str] = Field(default_factory=list, max_length=20)


@contextlib.contextmanager
def _errors():
    try:
        yield
    except (users.NotFound, apps.NotFound) as exc:
        raise HTTPException(404, str(exc)) from exc
    except (users.UserError, apps.AppError, federation.FederationError) as exc:
        raise HTTPException(422, str(exc)) from exc


def build_router(auth, keys_forget) -> APIRouter:
    r = APIRouter(prefix="/api")
    write, read = Depends(auth.require("*")), Depends(auth.require("admin:read"))

    def actor(p) -> str:
        return p.actor

    @r.get("/overview", dependencies=[read])
    def overview():
        with db.connect() as conn:
            counts = conn.execute("SELECT (SELECT count(*) FROM idp_user) AS users, (SELECT count(*) FROM idp_user WHERE status='active') AS active_users, "
                                  "(SELECT count(*) FROM idp_group) AS groups, (SELECT count(*) FROM idp_app) AS apps, "
                                  "(SELECT count(*) FROM idp_role_grant) AS grants, (SELECT count(*) FROM oauth_refresh WHERE revoked_at IS NULL AND used_at IS NULL "
                                  "AND expires_at > now()) AS live_refresh_tokens").fetchone()
            counts["vault"] = vault.status(conn)
            counts["signing_keys"] = keys.list_keys(conn)
            counts["providers"] = federation.enabled(conn)
        return counts

    # ---- users ----
    @r.get("/users", dependencies=[read])
    def list_users(q: str | None = None):
        with db.connect() as conn:
            return users.listing(conn, q)

    @r.post("/users", status_code=201)
    def create_user(body: UserBody, p=write):
        with _errors(), db.connect() as conn:
            u = users.create_user(conn, **body.model_dump())
            audit.log(conn, actor(p), "user_created", u["username"])
            conn.commit()
            return u

    @r.get("/users/{user_id}", dependencies=[read])
    def get_user(user_id: str):
        with _errors(), db.connect() as conn:
            return {**users.get(conn, user_id), "grants": [g for g in users.grants(conn) if g["subject_type"] == "user" and g["subject_id"] == user_id],
                    "federated": conn.execute("SELECT provider, email, created_at FROM idp_federated WHERE user_id=%s", (user_id,)).fetchall()}

    @r.patch("/users/{user_id}")
    def patch_user(user_id: str, body: UserPatch, p=write):
        with _errors(), db.connect() as conn:
            u = users.update(conn, user_id, **body.model_dump(exclude_unset=True))
            audit.log(conn, actor(p), "user_updated", u["username"], **body.model_dump(exclude_unset=True))
            conn.commit()
            return u

    @r.put("/users/{user_id}/password")
    def reset_password(user_id: str, body: PasswordBody, p=write):
        with _errors(), db.connect() as conn:
            users.set_password(conn, user_id, body.password)
            audit.log(conn, actor(p), "password_reset", user_id)
            conn.commit()
        return {"ok": True}

    @r.delete("/users/{user_id}")
    def delete_user(user_id: str, p=write):
        with _errors(), db.connect() as conn:
            name = users.get(conn, user_id)["username"]
            users.delete(conn, user_id)
            audit.log(conn, actor(p), "user_deleted", name)
            conn.commit()
        return {"deleted": user_id}

    @r.post("/users/{user_id}/groups")
    def add_member(user_id: str, body: MemberBody, p=write):
        with _errors(), db.connect() as conn:
            users.get(conn, user_id)
            users.add_to_group(conn, user_id, body.group)
            audit.log(conn, actor(p), "group_member_added", body.group, user=user_id)
            conn.commit()
            return users.get(conn, user_id)

    @r.delete("/users/{user_id}/groups/{group}")
    def remove_member(user_id: str, group: str, p=write):
        with _errors(), db.connect() as conn:
            users.remove_from_group(conn, user_id, group)
            audit.log(conn, actor(p), "group_member_removed", group, user=user_id)
            conn.commit()
            return users.get(conn, user_id)

    # ---- groups ----
    @r.get("/groups", dependencies=[read])
    def list_groups():
        with db.connect() as conn:
            return users.groups(conn)

    @r.post("/groups", status_code=201)
    def create_group(body: GroupBody, p=write):
        with _errors(), db.connect() as conn:
            g = users.create_group(conn, body.name, body.description)
            audit.log(conn, actor(p), "group_created", g["name"])
            conn.commit()
            return g

    @r.delete("/groups/{name}")
    def delete_group(name: str, p=write):
        with _errors(), db.connect() as conn:
            users.delete_group(conn, name)
            audit.log(conn, actor(p), "group_deleted", name)
            conn.commit()
        return {"deleted": name}

    # ---- apps ----
    @r.get("/apps", dependencies=[read])
    def list_apps():
        with db.connect() as conn:
            return apps.listing(conn)

    @r.post("/apps", status_code=201)
    def register_app(body: AppBody, p=write):
        d = body.model_dump()
        with _errors(), db.connect() as conn:
            app, secret = apps.register(conn, d.pop("client_id"), d.pop("name"), d.pop("kind"), d)
            audit.log(conn, actor(p), "app_registered", app["client_id"], kind=app["kind"])
            conn.commit()
        return {"app": app, "client_secret": secret}

    @r.get("/apps/{client_id}", dependencies=[read])
    def get_app(client_id: str):
        with _errors(), db.connect() as conn:
            return {**apps.get(conn, client_id), "grants": users.grants(conn, client_id)}

    @r.patch("/apps/{client_id}")
    def patch_app(client_id: str, body: AppPatch, p=write):
        with _errors(), db.connect() as conn:
            app = apps.update(conn, client_id, body.model_dump(exclude_unset=True))
            audit.log(conn, actor(p), "app_updated", client_id, fields=sorted(body.model_dump(exclude_unset=True)))
            conn.commit()
            return app

    @r.post("/apps/{client_id}/secret")
    def rotate_secret(client_id: str, p=write):
        with _errors(), db.connect() as conn:
            secret = apps.rotate_secret(conn, client_id)
            audit.log(conn, actor(p), "app_secret_rotated", client_id)
            conn.commit()
        return {"client_secret": secret}

    @r.delete("/apps/{client_id}")
    def delete_app(client_id: str, p=write):
        with _errors(), db.connect() as conn:
            apps.delete(conn, client_id)
            audit.log(conn, actor(p), "app_deleted", client_id)
            conn.commit()
        return {"deleted": client_id}

    # ---- role grants ----
    @r.get("/grants", dependencies=[read])
    def list_grants(client_id: str | None = None):
        with db.connect() as conn:
            return users.grants(conn, client_id)

    @r.post("/grants", status_code=201)
    def grant(body: GrantBody, p=write):
        with _errors(), db.connect() as conn:
            users.grant_role(conn, body.subject_type, body.subject, body.client_id, body.role)
            audit.log(conn, actor(p), "role_granted", f"{body.client_id}:{body.role}", subject=f"{body.subject_type}:{body.subject}")
            conn.commit()
        return {"ok": True}

    @r.delete("/grants/{grant_id}")
    def revoke(grant_id: int, p=write):
        with _errors(), db.connect() as conn:
            if not users.revoke_role(conn, grant_id):
                raise HTTPException(404, "no such grant")
            audit.log(conn, actor(p), "role_revoked", str(grant_id))
            conn.commit()
        return {"revoked": grant_id}

    # ---- signing keys ----
    @r.get("/keys", dependencies=[read])
    def list_keys():
        with db.connect() as conn:
            return keys.list_keys(conn)

    @r.post("/keys/rotate")
    def rotate_keys(p=write):
        if not vault.is_unlocked():
            raise HTTPException(423, "unlock the vault first")
        with db.connect() as conn:
            kid = keys.rotate(conn)
            audit.log(conn, actor(p), "signing_key_rotated", kid)
            conn.commit()
        keys_forget()
        return {"kid": kid}

    # ---- federation ----
    @r.get("/federation", dependencies=[read])
    def list_providers():
        with db.connect() as conn:
            return {"providers": federation.list_providers(conn), "available": federation.PROVIDERS}

    @r.put("/federation/{provider}")
    def put_provider(provider: str, body: ProviderBody, p=write):
        with _errors(), db.connect() as conn:
            out = federation.upsert_provider(conn, provider, body.client_id, body.client_secret, enabled=body.enabled, mode=body.mode,
                                             allowed_domains=body.allowed_domains, default_groups=body.default_groups)
            audit.log(conn, actor(p), "federation_configured", provider, mode=body.mode, enabled=body.enabled)
            conn.commit()
            return out

    @r.delete("/federation/{provider}")
    def drop_provider(provider: str, p=write):
        with db.connect() as conn:
            federation.delete_provider(conn, provider)
            audit.log(conn, actor(p), "federation_removed", provider)
            conn.commit()
        return {"deleted": provider}

    @r.get("/audit", dependencies=[read])
    def get_audit(limit: int = 200):
        with db.connect() as conn:
            return audit.recent(conn, max(1, min(limit, 500)))

    return r


__all__ = ["build_router", "core"]
