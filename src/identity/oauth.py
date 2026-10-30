"""The OAuth 2.0 / OpenID Connect server, built on Authlib's grant implementations.

What we add on top of Authlib, and why:
  * PKCE is mandatory for every client and only S256 is accepted (no `plain`).
  * Redirect URIs match exactly. Clients are bound to the grants their kind allows (web/public: code + refresh; service: client credentials).
  * Requested scopes must be ones the client is allowed; a service's scopes must all belong to one audience app it may call.
  * Access tokens are short-lived RFC 9068 JWTs (RS256, `kid` in the header) carrying only the roles of the audience app.
  * Refresh tokens are issued only with `offline_access`, rotate on every use, and replaying a used one revokes the whole family.
  * Authorization codes live 60 seconds and are consumed atomically: the row is deleted and returned by a single statement, so two
    concurrent redemptions cannot both succeed.
  * A refresh token is claimed with a conditional UPDATE (`used_at IS NULL`) before anything is issued; losing that race is treated as reuse.
"""
import hmac
import os
import secrets
import time
from datetime import UTC, datetime, timedelta

from apgkit.ids import sha256
from authlib.oauth2.rfc6749 import (
    AuthorizationServer,
    ClientMixin,
    InvalidScopeError,
    OAuth2Error,
    TokenMixin,
)
from authlib.oauth2.rfc6749.errors import InvalidGrantError, InvalidRequestError
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload, OAuth2Request
from authlib.oauth2.rfc6750 import BearerTokenGenerator  # noqa: F401  (documented base of the generator below)
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from authlib.oidc.core.grants import OpenIDCode
from joserfc import jwt

from . import core, keys, users
from .apps import STANDARD_SCOPES

ACCESS_TTL = 600            # seconds: short, so a disabled user or revoked role bites quickly
ID_TTL = 600
REFRESH_TTL = 30 * 86400    # the default; IDENTITY_REFRESH_TTL_DAYS overrides it (read when a refresh token is issued, see refresh_ttl)
CODE_TTL = 60
USER_GRANTS = {"authorization_code", "refresh_token"}
SERVICE_GRANTS = {"client_credentials"}


def refresh_ttl() -> int:
    """Seconds a refresh token lives: IDENTITY_REFRESH_TTL_DAYS (1 to 365; a bad value is ignored), else the 30-day default.
    Applies to tokens issued after the change; tokens already issued keep the expiry they were stored with."""
    try:
        days = float(os.environ.get("IDENTITY_REFRESH_TTL_DAYS", ""))
    except ValueError:
        return REFRESH_TTL
    return int(days * 86400) if 1 <= days <= 365 else REFRESH_TTL


class Client(ClientMixin):
    def __init__(self, row: dict):
        self.row = row
        self.client_id = row["client_id"]

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.row["redirect_uris"][0] if self.row["redirect_uris"] else None

    def get_allowed_scope(self, scope):
        allowed = set(STANDARD_SCOPES) | set(self.row["allowed_scopes"])
        return " ".join(s for s in (scope or "").split() if s in allowed) if self.row["kind"] != "service" else \
            " ".join(s for s in (scope or "").split() if s in set(self.row["allowed_scopes"]))

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.row["redirect_uris"]          # exact string match, never a prefix or pattern

    def check_client_secret(self, client_secret):
        stored = self.row.get("secret_hash")
        return bool(stored) and hmac.compare_digest(sha256(client_secret or ""), stored)

    def check_endpoint_auth_method(self, method, endpoint):
        if self.row["kind"] == "public":
            return method == "none"
        return method in {"client_secret_basic", "client_secret_post"}

    def check_response_type(self, response_type):
        return response_type == "code" and self.row["kind"] != "service"

    def check_grant_type(self, grant_type):
        return grant_type in (SERVICE_GRANTS if self.row["kind"] == "service" else USER_GRANTS)


class User:
    """The subject of a token request, carrying which app it is being issued for (roles are per app)."""

    def __init__(self, row: dict, client_id: str):
        self.row, self.client_id = row, client_id

    def get_user_id(self):
        return self.row["id"]


def _roles(user: User) -> list[str]:
    with core.db.connect(retries=1) as conn:
        return users.roles_for(conn, user.row["id"], user.client_id)


class AuthCode:
    def __init__(self, row: dict):
        self.row = row
        self.code_challenge, self.code_challenge_method = row["code_challenge"], row["challenge_method"]
        self.client_id, self.user_id = row["client_id"], row["user_id"]

    def get_redirect_uri(self):
        return self.row["redirect_uri"]

    def get_scope(self):
        return self.row["scope"]

    def get_nonce(self):
        return self.row["nonce"]

    def get_auth_time(self):
        return self.row["auth_time"]

    def get_acr(self):
        return None

    def get_amr(self):
        return None


class RefreshRecord(TokenMixin):
    def __init__(self, row: dict):
        self.row = row
        self.family_id, self.user_id, self.client_id = row["family_id"], row["user_id"], row["client_id"]

    def check_client(self, client):
        return client.get_client_id() == self.client_id

    def get_scope(self):
        return self.row["scope"]

    def get_expires_in(self):
        return int((self.row["expires_at"] - datetime.now(UTC)).total_seconds())

    def is_expired(self):
        return self.row["expires_at"] <= datetime.now(UTC)

    def is_revoked(self):
        return self.row["revoked_at"] is not None


class ScopePolicy:
    """Reject (rather than silently trim) scopes the client may not request; keep a service to one audience."""

    def validate_requested_scope(self):
        scope = self.request.payload.scope
        client = self.request.client if self.request.client else None
        if not scope or client is None:
            return
        wanted = scope.split()
        if set(wanted) - set(client.get_allowed_scope(scope).split()):
            raise InvalidScopeError()
        if client.row["kind"] == "service" and len(audience_of(client, wanted)) != 1:
            raise InvalidScopeError(description="a service token may carry scopes of one audience app only")


def audience_of(client: Client, scopes: list[str]) -> set[str]:
    """Apps a set of service scopes addresses: the part before the first dot (`trustdesk.requests.write` -> `trustdesk`).
    Each must be the service itself or an app it is allowed to call."""
    out = set()
    for s in scopes:
        app = s.split(".", 1)[0] if "." in s else client.client_id
        if app != client.client_id and app not in client.row["allowed_audiences"]:
            return set()
        out.add(app)
    return out or {client.client_id}


class StrictPKCE(CodeChallenge):
    """Authlib only insists on PKCE for public clients and quietly accepts a request with no challenge. Here every client must
    send a code_challenge with method S256 when asking for a code, and the matching code_verifier when redeeming it."""

    def validate_code_challenge(self, grant, redirect_uri):
        data = grant.request.payload.data
        if not data.get("code_challenge"):
            raise InvalidRequestError("Missing 'code_challenge': PKCE is required for every client.", redirect_uri=redirect_uri)
        if data.get("code_challenge_method") != "S256":
            raise InvalidRequestError("'code_challenge_method' must be S256.", redirect_uri=redirect_uri)
        super().validate_code_challenge(grant, redirect_uri)

    def validate_code_verifier(self, grant, result):
        try:
            if not grant.request.form.get("code_verifier"):
                raise InvalidRequestError("Missing 'code_verifier'.")
            super().validate_code_verifier(grant, result)
        except OAuth2Error:
            # a wrong or missing verifier burns the code, so it cannot be tried again
            if grant.request.authorization_code is not None:
                grant.delete_authorization_code(grant.request.authorization_code)
            raise


class CodeGrant(ScopePolicy, AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        data = request.payload.data
        with core.db.connect(retries=1) as conn:
            conn.execute("INSERT INTO oauth_code (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, challenge_method, "
                         "auth_time, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                         (sha256(code), request.client.get_client_id(), request.user["id"], request.payload.redirect_uri,
                          request.scope or "", data.get("nonce"), data["code_challenge"], "S256", request.user.get("auth_time", int(time.time())),
                          datetime.now(UTC) + timedelta(seconds=CODE_TTL)))
            conn.commit()

    def query_authorization_code(self, code, client):
        # Consuming the code here (DELETE ... RETURNING) makes redemption single-use even under concurrency: only one caller gets the row.
        with core.db.connect(retries=1) as conn:
            row = conn.execute("DELETE FROM oauth_code WHERE code_hash=%s AND client_id=%s AND expires_at > now() RETURNING *",
                               (sha256(code), client.get_client_id())).fetchone()
            conn.commit()
        return AuthCode(row) if row else None

    def delete_authorization_code(self, authorization_code):
        with core.db.connect(retries=1) as conn:
            conn.execute("DELETE FROM oauth_code WHERE code_hash=%s", (authorization_code.row["code_hash"],))
            conn.commit()

    def authenticate_user(self, authorization_code):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT id, username, email, name, status FROM idp_user WHERE id=%s", (authorization_code.user_id,)).fetchone()
        return User(row, authorization_code.client_id) if row and row["status"] == "active" else None


class RefreshGrant(ScopePolicy, RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT * FROM oauth_refresh WHERE token_hash=%s", (sha256(refresh_token),)).fetchone()
            if not row:
                return None
            if row["used_at"] is not None or row["revoked_at"] is not None:
                # a token that was already used (or revoked) is being presented again: assume theft and kill the whole family
                conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE family_id=%s AND revoked_at IS NULL", (row["family_id"],))
                conn.commit()
                return None
        rec = RefreshRecord(row)
        return None if rec.is_expired() else rec

    def authenticate_user(self, refresh_token):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT id, username, email, name, status FROM idp_user WHERE id=%s", (refresh_token.user_id,)).fetchone()
        return User(row, refresh_token.client_id) if row and row["status"] == "active" else None

    def create_token_response(self):
        """Claim the presented token first: the conditional UPDATE is the single-use gate. A concurrent second request with the same
        token gets no row back, is treated as reuse, and the whole family is revoked."""
        record = self.request.refresh_token
        with core.db.connect(retries=1) as conn:
            claimed = conn.execute("UPDATE oauth_refresh SET used_at = now() WHERE id=%s AND used_at IS NULL AND revoked_at IS NULL RETURNING id",
                                   (record.row["id"],)).fetchone()
            if not claimed:
                conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE family_id=%s AND revoked_at IS NULL", (record.family_id,))
            conn.commit()
        if not claimed:
            raise InvalidGrantError("Invalid 'refresh_token' in request.")
        return super().create_token_response()

    def revoke_old_credential(self, refresh_token):
        """Nothing left to do: create_token_response already marked the token used before issuing its replacement."""


class ServiceGrant(ScopePolicy, ClientCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]


class IdToken(OpenIDCode):
    def __init__(self, issuer: str):
        super().__init__(require_nonce=False)
        self.issuer = issuer

    def exists_nonce(self, nonce, request):
        return False                                # codes are single-use and short-lived; replay is handled there

    def resolve_client_private_key(self, client):
        with core.db.connect(retries=1) as conn:
            return keys.signing_key(conn)

    def get_client_algorithm(self, client):
        return "RS256"

    def get_encode_header(self, client):
        with core.db.connect(retries=1) as conn:
            return {"alg": "RS256", "kid": keys.signing_key(conn).kid}

    def get_client_claims(self, client):
        return {"iss": self.issuer, "aud": [client.get_client_id()], "exp": int(time.time()) + ID_TTL}

    def generate_user_info(self, user, scope):
        info = {"sub": user.row["id"]}
        scopes = (scope or "").split()
        if "profile" in scopes:
            info.update(name=user.row["name"] or user.row["username"], preferred_username=user.row["username"])
        if "email" in scopes:
            info["email"] = user.row["email"]
        if "roles" in scopes:
            info["roles"] = _roles(user)
        return info


class TokenGenerator(JWTBearerTokenGenerator):
    """RFC 9068 access tokens with a `kid`; roles of the audience app; refresh tokens only with offline_access."""

    def __init__(self, issuer):
        super().__init__(issuer, refresh_token_generator=lambda *a, **k: "rt_" + secrets.token_urlsafe(40), expires_generator=lambda *a: ACCESS_TTL)

    def generate(self, grant_type, client, user=None, scope=None, expires_in=None, include_refresh_token=True):
        wants_refresh = include_refresh_token and user is not None and "offline_access" in (scope or "").split() and grant_type != "client_credentials"
        return super().generate(grant_type, client, user, scope, expires_in, wants_refresh)

    def get_audiences(self, client, user, scope):
        if user is None:
            return sorted(audience_of(client, (scope or "").split()))[0]
        return client.get_client_id()

    def get_extra_claims(self, client, grant_type, user, scope):
        if user is None:
            return {"sub_type": "service", "client_name": client.row["name"]}
        return {"sub_type": "user", "name": user.row["name"] or user.row["username"], "email": user.row["email"], "roles": _roles(user)}

    def access_token_generator(self, client, grant_type, user, scope):
        now = int(time.time())
        claims = {"iss": self.issuer, "exp": now + ACCESS_TTL, "iat": now, "client_id": client.get_client_id(), "jti": self.get_jti(client, grant_type, user, scope),
                  "scope": scope or "", "sub": str(user.get_user_id()) if user else client.get_client_id(),
                  "aud": self.get_audiences(client, user, scope)}
        claims.update(self.get_extra_claims(client, grant_type, user, scope))
        with core.db.connect(retries=1) as conn:
            key = keys.signing_key(conn)
        return jwt.encode({"alg": "RS256", "typ": "at+jwt", "kid": key.kid}, claims, key)


class StarletteRequest(OAuth2Request):
    """Authlib's request for a Starlette request whose form and query were read by the endpoint."""

    def __init__(self, method: str, uri: str, data: dict, headers: dict):
        super().__init__(method, uri, None, headers)
        self.payload = BasicOAuth2Payload(data)
        self._data = data

    @property
    def args(self):
        return self._data

    @property
    def form(self):
        return self._data


class _Revocation(RevocationEndpoint):
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def query_token(self, token_string, token_type_hint):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT * FROM oauth_refresh WHERE token_hash=%s", (sha256(token_string),)).fetchone()
        return RefreshRecord(row) if row else None

    def revoke_token(self, token, request):
        with core.db.connect(retries=1) as conn:
            conn.execute("UPDATE oauth_refresh SET revoked_at = now() WHERE family_id=%s AND revoked_at IS NULL", (token.family_id,))
            conn.commit()


class _Introspection(IntrospectionEndpoint):
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    def query_token(self, token_string, token_type_hint):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT * FROM oauth_refresh WHERE token_hash=%s", (sha256(token_string),)).fetchone()
        return RefreshRecord(row) if row else None

    def check_permission(self, token, client, request):
        return token.client_id == client.get_client_id()

    def introspect_token(self, token):
        return {"active": not token.is_expired() and not token.is_revoked() and token.row["used_at"] is None, "client_id": token.client_id,
                "scope": token.get_scope(), "sub": token.user_id, "token_type": "refresh_token"}


class IdentityServer(AuthorizationServer):
    def __init__(self, issuer: str):
        super().__init__()
        self.issuer = issuer
        self.register_token_generator("default", TokenGenerator(issuer))
        self.register_grant(CodeGrant, [StrictPKCE(required=True), IdToken(issuer)])
        self.register_grant(RefreshGrant)
        self.register_grant(ServiceGrant)
        self.register_endpoint(_Revocation)
        self.register_endpoint(_Introspection)
        # only S256 is acceptable (the extension also lists `plain`)
        CodeChallenge.SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]
        CodeChallenge.DEFAULT_CODE_CHALLENGE_METHOD = "S256"

    def query_client(self, client_id):
        with core.db.connect(retries=1) as conn:
            row = conn.execute("SELECT * FROM idp_app WHERE client_id=%s AND status='active'", (client_id,)).fetchone()
        return Client(row) if row else None

    def save_token(self, token, request):
        if not token.get("refresh_token"):
            return
        family = request.refresh_token.family_id if request.refresh_token else "fam_" + secrets.token_urlsafe(12)
        user = request.user
        if request.refresh_token:
            auth_time = request.refresh_token.row["auth_time"]
        elif request.authorization_code:
            auth_time = request.authorization_code.get_auth_time()
        else:
            auth_time = int(time.time())
        with core.db.connect(retries=1) as conn:
            conn.execute("INSERT INTO oauth_refresh (token_hash, family_id, client_id, user_id, scope, auth_time, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                         (sha256(token["refresh_token"]), family, request.client.get_client_id(), user.get_user_id(), token.get("scope", ""),
                          auth_time, datetime.now(UTC) + timedelta(seconds=refresh_ttl())))
            conn.commit()

    def create_oauth2_request(self, request):
        return request

    def create_json_request(self, request):
        return request

    def handle_response(self, status, body, headers):
        return status, body, headers

    def send_signal(self, name, *args, **kwargs):
        return None


def verify_access_token(token: str, conn) -> dict | None:
    """Verify an access token this server issued (for /userinfo): signature against our own keys, issuer and expiry."""
    from joserfc.errors import JoseError
    from joserfc.jwk import KeySet
    from joserfc.jwt import JWTClaimsRegistry
    try:
        decoded = jwt.decode(token, KeySet.import_key_set(keys.jwks(conn)), algorithms=["RS256"])
        JWTClaimsRegistry(leeway=10, iss={"essential": True, "value": core_issuer()}, exp={"essential": True},
                          sub={"essential": True}).validate(decoded.claims)
        return dict(decoded.claims)
    except (JoseError, ValueError, KeyError):
        return None


_issuer: list[str] = [""]


def core_issuer() -> str:
    return _issuer[0]


def set_issuer(value: str) -> None:
    _issuer[0] = value
