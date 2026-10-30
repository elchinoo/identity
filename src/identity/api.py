import asyncio
import contextlib
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import psycopg
from apgkit import __version__ as kit_version  # noqa: F401
from apgkit import masking
from apgkit import vault as vault_mod
from apgkit.auth.rp import BINDING_COOKIE, clear_binding
from apgkit.guard import SecurityGuard
from apgkit.web import is_https, mount_kit_static, public_url
from authlib.oauth2.rfc6749 import OAuth2Error
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import __version__, apps, audit, core, federation, hardening, keys, oauth, users
from .core import COOKIE_ADMIN, COOKIE_SSO, CSRF_HEADER, auth, db, local, login_limiter, metrics, vault

STATIC = Path(__file__).resolve().parent / "static"
MASKING_EVERY = 300          # seconds between masking re-asserts (agentpg-kit apgkit.masking.reassert_forever)
_announced = False
_server: list[oauth.IdentityServer] = []


def _announce() -> None:
    global _announced
    if not _announced:
        _announced = True
        print("\n=== Identity first-run setup ===\n"
              "Open the app in your browser and enter this one-time code to create the admin password:\n"
              f"    {local.setup_code()}\n(It changes every time the server restarts until setup is complete.)\n", file=sys.stderr, flush=True)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        with db.connect(retries=2) as conn:
            core.check_encoding(conn)
            vault.try_unlock_with_platform_secret(conn)
            if not vault.is_initialized(conn) and vault.initialize_with_platform_secret(conn):
                conn.commit()                  # unattended first start: the platform secret alone protects the signing keys
            keys.ensure(conn)
            if local.needs_setup(conn):
                _announce()
    except core.DatabaseEncodingError as exc:
        print(f"\n!!! {exc}\n", file=sys.stderr, flush=True)       # /readyz reports it too; do not hide it behind "waking"
    except Exception:  # noqa: BLE001 - the database may be asleep; everything retries on the first request
        pass
    # Grants made after startup (`agentpg db-users create`, default privileges) reopen base tables, signing_key included: re-assert.
    reassert = asyncio.create_task(masking.reassert_forever(db.connect, hardening.apply, MASKING_EVERY, deny=hardening.DENY, metrics=metrics))
    try:
        yield
    finally:
        reassert.cancel()
        await asyncio.gather(reassert, return_exceptions=True)
        db.close_pool()


app = FastAPI(title="Identity", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityGuard, csrf_header=CSRF_HEADER, csrf_prefixes=("/api/", "/login"), body_prefixes=("/api/", "/login", "/oauth/"),
                   observe=metrics.observe)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
mount_kit_static(app)


def issuer_for(request: Request) -> str:
    return core.issuer(public_url(request, "IDENTITY_PUBLIC_URL"))


def server_for(request: Request) -> oauth.IdentityServer:
    if not _server:
        iss = issuer_for(request)
        oauth.set_issuer(iss)
        _server.append(oauth.IdentityServer(iss))
    return _server[0]


def reset_server() -> None:
    """For tests: forget the cached server (and so the issuer)."""
    _server.clear()


def _unavailable() -> HTTPException:
    return HTTPException(503, "database unavailable; it may be waking up, retry in a few seconds")


# ---- public: health, discovery, keys --------------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readyz():
    try:
        with db.connect(retries=1) as conn:
            core.check_encoding(conn)
            ready = keys.can_sign(conn)
        return {"status": "ready", "masking": masking.status()} if ready else JSONResponse({"status": "locked", "detail": "no signing key: unlock the vault"}, status_code=503)
    except core.DatabaseEncodingError as exc:
        return JSONResponse({"status": "bad-database-encoding", "detail": str(exc)}, status_code=503)
    except Exception:  # noqa: BLE001
        return JSONResponse({"status": "waking-database"}, status_code=503)


@app.get("/metrics", dependencies=[Depends(auth.require("metrics:scrape"))])
def prometheus_metrics():
    body, ctype = metrics.render()
    return Response(body, media_type=ctype)


@app.get("/.well-known/openid-configuration")
def discovery(request: Request):
    iss = issuer_for(request)
    return {"issuer": iss, "authorization_endpoint": f"{iss}/oauth/authorize", "token_endpoint": f"{iss}/oauth/token", "userinfo_endpoint": f"{iss}/oauth/userinfo",
            "jwks_uri": f"{iss}/jwks.json", "end_session_endpoint": f"{iss}/oauth/logout", "revocation_endpoint": f"{iss}/oauth/revoke",
            "introspection_endpoint": f"{iss}/oauth/introspect", "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "scopes_supported": list(apps.STANDARD_SCOPES), "claims_supported": ["sub", "name", "preferred_username", "email", "roles", "auth_time", "nonce"]}


@app.get("/jwks.json")
def jwks():
    with db.connect() as conn:
        return JSONResponse(keys.jwks(conn), headers={"Cache-Control": "public, max-age=300"})


# ---- the end user: sign-in, SSO session, launcher ---------------------------------------------------------------------------
def sso_user(request: Request) -> dict | None:
    """The signed-in person (SSO cookie), as {id, ...}, or None. Never an administrator: this cookie opens no admin API."""
    raw = request.cookies.get(COOKIE_SSO)
    if not raw:
        return None
    with db.connect(retries=1) as conn:
        p = local.session_principal(conn, raw)
        if not p or p.source != "idp":
            return None
        row = conn.execute("SELECT id, username, email, name, status FROM idp_user WHERE id=%s", (p.subject,)).fetchone()
    return row if row and row["status"] == "active" else None


def start_sso(conn, request: Request, response: Response, user: dict) -> None:
    raw = local.create_session(conn, subject=user["id"], name=user["name"] or user["username"], email=user["email"], source="idp")
    response.set_cookie(COOKIE_SSO, raw, httponly=True, samesite="lax", secure=is_https(request), max_age=12 * 3600, path="/")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginBody(_Body):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    next: str | None = Field(None, max_length=2048)


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html")


@app.get("/api/login-options")
def login_options():
    with db.connect() as conn:
        return {"password": True, "providers": federation.enabled(conn)}


@app.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    ip = auth.client(request)
    who = body.username.strip().lower()
    if login_limiter.limited(ip) or login_limiter.limited("u:" + who):
        raise HTTPException(429, "too many failed attempts; wait a few minutes")
    try:
        with db.connect(retries=1) as conn:
            user = users.authenticate(conn, body.username, body.password)
            if not user:
                login_limiter.record(ip)
                login_limiter.record("u:" + who)
                audit.log(conn, "anonymous", "login_failed", who)
                conn.commit()
                raise HTTPException(401, "that username or password is not right")
            start_sso(conn, request, response, user)
    except (psycopg.Error, RuntimeError) as exc:
        raise _unavailable() from exc
    return {"next": core.safe_next(body.next)}


@app.get("/login/{provider}")
def login_upstream(provider: str, request: Request, next: str | None = None):
    try:
        with db.connect(retries=1) as conn:
            login = federation.begin(conn, provider, public_url(request, "IDENTITY_PUBLIC_URL"), next)
    except federation.FederationError as exc:
        return RedirectResponse(f"/login?{urlencode({'error': str(exc)})}", status_code=303)
    resp = RedirectResponse(login.url, status_code=303)
    login.bind(resp, secure=is_https(request))             # the kit's browser-binding cookie: the callback must arrive in this browser
    return resp


def _fed_failed(request: Request, message: str) -> RedirectResponse:
    resp = RedirectResponse(f"/login?{urlencode({'error': message})}", status_code=303)
    clear_binding(resp, secure=is_https(request))
    return resp


@app.get("/login/{provider}/callback")
def login_upstream_callback(provider: str, request: Request, code: str = "", state: str = "", error: str = ""):
    if error or not code or not state:
        return _fed_failed(request, "the sign-in was cancelled or failed")
    try:
        with db.connect(retries=1) as conn:
            user, back = federation.finish(conn, provider, public_url(request, "IDENTITY_PUBLIC_URL"), code, state, request.cookies.get(BINDING_COOKIE))
            resp = RedirectResponse(back, status_code=303)
            start_sso(conn, request, resp, user)
            audit.log(conn, user["username"], "login_federated", provider)
            conn.commit()
            clear_binding(resp, secure=is_https(request))
            return resp
    except federation.FederationError as exc:
        return _fed_failed(request, str(exc))


@app.post("/logout")
def sso_logout(request: Request, response: Response):
    with db.connect(retries=1) as conn:
        local.delete_session(conn, request.cookies.get(COOKIE_SSO))
    response.delete_cookie(COOKIE_SSO, path="/")
    return {"ok": True}


@app.get("/apps")
def launcher_page():
    return FileResponse(STATIC / "apps.html")


@app.get("/api/my-apps")
def my_apps(request: Request):
    user = sso_user(request)
    if not user:
        raise HTTPException(401, "sign in first")
    with db.connect() as conn:
        out = []
        for a in conn.execute("SELECT client_id, name, description, url FROM idp_app WHERE status='active' AND url <> '' AND kind <> 'service' ORDER BY name").fetchall():
            roles = users.roles_for(conn, user["id"], a["client_id"])
            if roles:
                out.append({**a, "roles": [r.split(":", 1)[1] for r in roles]})
    return {"user": {"username": user["username"], "name": user["name"], "email": user["email"]}, "apps": out}


# ---- OAuth 2.0 / OpenID Connect endpoints ------------------------------------------------------------------------------------
def _oauth_request(request: Request, data: dict) -> oauth.StarletteRequest:
    headers = {}
    if request.headers.get("authorization"):
        headers["Authorization"] = request.headers["authorization"]
    return oauth.StarletteRequest(request.method, str(request.url), data, headers)


def _json(status: int, body, headers) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=dict(headers or {}))


def _oauth_error(exc: OAuth2Error) -> Response:
    status, body, headers = exc()
    return _json(status, body, headers)


@app.get("/oauth/authorize")
async def authorize(request: Request):
    server = server_for(request)
    data = dict(request.query_params)
    oreq = _oauth_request(request, data)
    user = await run_in_threadpool(sso_user, request)

    def run():
        try:
            grant = server.get_consent_grant(request=oreq, end_user={"id": user["id"]} if user else None)
        except OAuth2Error as exc:
            if getattr(exc, "redirect_uri", None):
                status, body, headers = exc()
                return RedirectResponse(dict(headers).get("Location") or exc.redirect_uri, status_code=302) if dict(headers).get("Location") else _json(status, body, headers)
            return _oauth_error(exc)
        if not user:
            return RedirectResponse("/login?" + urlencode({"next": str(request.url.path) + "?" + str(request.url.query)}), status_code=302)
        with db.connect(retries=1) as conn:
            audit.log(conn, user["username"], "authorize", grant.client.get_client_id())
            conn.commit()
        status, body, headers = server.create_authorization_response(request=oreq, grant_user={"id": user["id"], "auth_time": int(time.time())})
        location = dict(headers).get("Location")
        return RedirectResponse(location, status_code=302) if location else _json(status, body, headers)

    return await run_in_threadpool(run)


@app.post("/oauth/token")
async def token(request: Request):
    server = server_for(request)
    form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
    oreq = _oauth_request(request, form)

    def run():
        try:
            status, body, headers = server.create_token_response(request=oreq)
        except (RuntimeError, vault_mod.VaultError) as exc:      # no signing key available (the vault is locked)
            return JSONResponse({"error": "temporarily_unavailable", "error_description": "tokens cannot be signed right now: " + str(exc)[:120]},
                                status_code=503, headers={"Retry-After": "30", "Cache-Control": "no-store"})
        return _json(status, body, headers)
    return await run_in_threadpool(run)


@app.post("/oauth/revoke")
async def revoke(request: Request):
    server = server_for(request)
    oreq = _oauth_request(request, {k: v for k, v in (await request.form()).items() if isinstance(v, str)})
    return await run_in_threadpool(lambda: _json(*server.create_endpoint_response("revocation", oreq)))


@app.post("/oauth/introspect")
async def introspect(request: Request):
    server = server_for(request)
    oreq = _oauth_request(request, {k: v for k, v in (await request.form()).items() if isinstance(v, str)})
    return await run_in_threadpool(lambda: _json(*server.create_endpoint_response("introspection", oreq)))


@app.api_route("/oauth/userinfo", methods=["GET", "POST"])
def userinfo(request: Request):
    server_for(request)
    header = request.headers.get("authorization", "")
    if header[:7].lower() != "bearer ":
        raise HTTPException(401, "bearer token required", headers={"WWW-Authenticate": "Bearer"})
    with db.connect() as conn:
        claims = oauth.verify_access_token(header[7:].strip(), conn)
    if not claims or claims.get("sub_type") != "user":
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    return {k: claims[k] for k in ("sub", "name", "email", "roles") if k in claims}


@app.get("/oauth/logout")
def end_session(request: Request, response: Response, post_logout_redirect_uri: str | None = None, state: str | None = None,
                client_id: str | None = None, id_token_hint: str | None = None):
    """RP-initiated logout: end the SSO session; go back to the app only to a URI it registered."""
    target = None
    if post_logout_redirect_uri:
        cid = client_id
        if not cid and id_token_hint:
            with contextlib.suppress(Exception):
                from joserfc import jwt as _jwt
                cid = _jwt.decode(id_token_hint, key=_hint_keys(), algorithms=["RS256"]).claims.get("aud")
                cid = cid[0] if isinstance(cid, list) else cid
        if cid:
            with db.connect(retries=1) as conn:
                row = conn.execute("SELECT post_logout_uris FROM idp_app WHERE client_id=%s", (cid,)).fetchone()
            if row and post_logout_redirect_uri in row["post_logout_uris"]:
                target = post_logout_redirect_uri + (("&" if "?" in post_logout_redirect_uri else "?") + urlencode({"state": state}) if state else "")
    with db.connect(retries=1) as conn:
        local.delete_session(conn, request.cookies.get(COOKIE_SSO))
    resp = RedirectResponse(target or "/login?" + urlencode({"message": "You are signed out."}), status_code=302)
    resp.delete_cookie(COOKIE_SSO, path="/")
    return resp


def _hint_keys():
    from joserfc.jwk import KeySet
    with db.connect(retries=1) as conn:
        return KeySet.import_key_set(keys.jwks(conn))


# ---- operator console API -----------------------------------------------------------------------------------------------------
class SetupBody(_Body):
    code: str = Field(max_length=64)
    password: str = Field(max_length=256)


class AdminLoginBody(_Body):
    password: str | None = Field(None, max_length=256)
    api_key: str | None = Field(None, max_length=512)


class UnlockBody(_Body):
    password: str = Field(max_length=256)


class PasswordBody(_Body):
    current: str | None = Field(None, max_length=256)
    new: str = Field(max_length=256)


class TokenBody(_Body):
    name: str = Field(min_length=1, max_length=60)
    scope: str = Field(pattern="^(read|metrics|full)$")


def _admin_session(conn, request: Request, response: Response) -> None:
    raw = local.create_session(conn)
    response.set_cookie(COOKIE_ADMIN, raw, httponly=True, samesite="strict", secure=is_https(request), max_age=12 * 3600, path="/")
    keys.ensure(conn)


def _guard(request: Request) -> str:
    ip = auth.client(request)
    if auth.limiter.limited(ip):
        raise HTTPException(429, "too many failed attempts; wait a minute")
    return ip


@app.get("/admin")
def admin_page():
    return FileResponse(STATIC / "index.html")


@app.get("/")
def root(request: Request):
    return RedirectResponse("/apps" if request.cookies.get(COOKIE_SSO) else "/login", status_code=302)


@app.get("/api/session")
def session_state(request: Request):
    principal = None
    try:
        principal = auth.authenticate(request)
        with db.connect(retries=1) as conn:
            setup = local.needs_setup(conn)
            v = vault.status(conn)
            has_password = local.admin_configured(conn)
            signing = keys.can_sign(conn)
    except HTTPException:
        raise
    except (psycopg.Error, RuntimeError) as exc:
        raise _unavailable() from exc
    if setup:
        _announce()
    state = "setup_required" if setup else "logged_in" if principal else "logged_out"
    return {"state": state, "vault": v, "has_admin_password": has_password, "password_login": has_password,
            "key_login": local.static_key_configured(), "version": __version__, "signing_key": signing}


@app.post("/api/setup")
def setup(body: SetupBody, request: Request, response: Response):
    ip = _guard(request)
    try:
        with db.connect(retries=1) as conn:
            try:
                local.complete_setup(conn, body.code, body.password)
            except PermissionError as exc:
                auth.limiter.record(ip)
                raise HTTPException(403, str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            _admin_session(conn, request, response)
    except (psycopg.Error, RuntimeError) as exc:
        raise _unavailable() from exc
    return {"ok": True}


@app.post("/api/login")
def admin_login(body: AdminLoginBody, request: Request, response: Response):
    ip = auth.client(request)
    try:
        with db.connect(retries=1) as conn:
            ok = False
            if body.password is not None:
                # counted before hashing (one scrypt per attempt); 429 over the limit, 503 (ScryptBusy) when every scrypt slot is taken
                ok = local.login_password(conn, body.password, client=ip, limiter=auth.limiter)
            else:
                _guard(request)
                if body.api_key is not None and local.static_key_matches(body.api_key):
                    ok = True
                    vault.try_unlock_with_platform_secret(conn)
                else:
                    auth.limiter.record(ip)
            if not ok:
                raise HTTPException(401, "invalid credentials")
            _admin_session(conn, request, response)
    except (psycopg.Error, RuntimeError) as exc:
        raise _unavailable() from exc
    return {"ok": True}


@app.post("/api/logout")
def admin_logout(request: Request, response: Response):
    with contextlib.suppress(psycopg.Error, RuntimeError):
        with db.connect(retries=1) as conn:
            local.delete_session(conn, request.cookies.get(COOKIE_ADMIN))
    response.delete_cookie(COOKIE_ADMIN, path="/")
    return {"ok": True}


@app.post("/api/vault/unlock")
def unlock_vault(body: UnlockBody, request: Request, _=Depends(auth.require("*"))):
    ip = _guard(request)
    with db.connect() as conn:
        if not vault.is_initialized(conn):
            raise HTTPException(409, "set an admin password first")
        if not vault.unlock_with_password(conn, body.password):
            auth.limiter.record(ip)
            raise HTTPException(403, "wrong password")
        keys.ensure(conn)
        conn.commit()
    return {"ok": True}


@app.post("/api/admin-password")
def admin_password(body: PasswordBody, request: Request, _=Depends(auth.require("*"))):
    ip = _guard(request)
    with db.connect() as conn:
        try:
            if local.admin_configured(conn):
                if body.current is None:
                    raise HTTPException(422, "current password is required")
                local.change_password(conn, body.current, body.new)
            else:
                local.set_admin_password(conn, body.new)
        except PermissionError as exc:
            auth.limiter.record(ip)
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        conn.execute("DELETE FROM web_session WHERE source='local'")
        keys.ensure(conn)
        conn.commit()
    return {"ok": True, "signed_out_everywhere": True}


@app.get("/api/tokens")
def list_tokens(_=Depends(auth.require("*"))):
    with db.connect() as conn:
        return local.list_tokens(conn)


@app.post("/api/tokens")
def create_token(body: TokenBody, _=Depends(auth.require("*"))):
    with db.connect() as conn:
        tid, raw = local.create_token(conn, body.name.strip(), body.scope)
    return {"id": tid, "token": raw, "scope": body.scope, "name": body.name.strip()}


@app.delete("/api/tokens/{token_id}")
def revoke_token(token_id: int, _=Depends(auth.require("*"))):
    with db.connect() as conn:
        if not local.revoke_token(conn, token_id):
            raise HTTPException(404, "token not found or already revoked")
    return {"revoked": token_id}


from . import admin_api  # noqa: E402

app.include_router(admin_api.build_router(auth, keys_forget=keys.forget))
