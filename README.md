# Identity

The identity provider of the AgentPG ecosystem. One sign-in for every app, one place that says who may do what.

- **OpenID Connect and OAuth 2.0**: authorization code with **PKCE (S256, mandatory for every client)**, refresh tokens that
  **rotate** (replaying a used one revokes the whole family), `client_credentials` for services, discovery, JWKS,
  userinfo, introspection, revocation and RP-initiated logout. Grant logic comes from [Authlib](https://authlib.org);
  the strictness on top of it (mandatory PKCE, exact redirect URIs, scope policy, audiences) is this app's, and tested.
- **People, groups and roles per app.** An app defines its roles; people (directly, or through groups) hold them; an app
  may give every user a default role. Access tokens carry only the roles of the app they are for.
- **Federation**: sign in with **Google** (OIDC) or **GitHub** (OAuth 2.0), or with a local password. A verified e-mail
  links an upstream account to a user; `invite_only` (default) never creates users, `open` creates them for domains you list.
- **Service identities**: apps and jobs get tokens with `client_credentials` instead of hand-copied secrets, scoped to
  one audience app at a time.
- **Signing keys** are generated here (RS256), stored encrypted under the vault, rotated from the console (the old key
  stays published for 24 hours), and published as a JWKS that apps verify against locally. An **emergency rotation**
  (console API `POST /api/keys/emergency-rotate`, or `identity rotate-keys --emergency --yes`) removes every old key at once and
  revokes all refresh tokens and SSO sessions.
- Built from [`agentpg-kit`](https://github.com/elchinoo/agentpg-kit) blocks: config, Postgres, vault, security middleware,
  metrics, local admin, and the same OIDC pieces every app uses to log in. An audit trail records every change.

## Run it

```bash
cp .env.example .env     # set POSTGRES_PASSWORD
docker compose up -d db
uv venv && uv pip install -e ../agentpg-kit -e ".[dev]"   # or: pip install the kit release, then this app
set -a; . ./.env; set +a
identity start           # http://localhost:8000: the first start prints a one-time setup code
```

Open `/admin`, enter the setup code, choose the admin password. **Set `IDENTITY_ENCRYPTION_KEY`** (any long random value,
or a file via `IDENTITY_ENCRYPTION_KEY_FILE`) so the vault unlocks itself after a restart; without it the signing key is
unreadable after every restart until the admin signs in, and no token can be issued in between (`/readyz` says `locked`).

## Connect an app

1. **Apps -> Register an app**: client id (also the role namespace), kind (`web`: server-side with a secret; `public`:
   PKCE only; `service`: machine to machine), redirect URIs (exact; https or localhost), the roles it defines.
2. Give people roles (Users, or Groups).
3. In the app (any app built on the kit): `<APP>_OIDC_ISSUER=https://<identity>`, `<APP>_OIDC_CLIENT_ID`,
   `<APP>_OIDC_CLIENT_SECRET[_FILE]`. The app verifies tokens against `/jwks.json` and maps roles to its permissions.

Services: register a `service` app with `allowed_scopes` such as `trustdesk.requests.write` and `allowed_audiences`
such as `trustdesk`. Scopes address one audience app by their prefix.

## Configuration

| Variable | Meaning |
|---|---|
| `DATABASE_URL` / `DB_EXTERNAL_DSN` / `PSQL_CONNECTION_STRING` | Postgres, which must be a UTF-8 database. |
| `IDENTITY_PUBLIC_URL`, `IDENTITY_ISSUER` | The URL the provider is reached at; it becomes the token issuer, so set it once and keep it. Default: the first request's address. |
| `IDENTITY_ENCRYPTION_KEY[_FILE]` | Platform secret that unlocks the vault (signing keys, provider secrets) at startup. |
| `IDENTITY_API_KEY[_FILE]` | Optional static full-access key for automation. At least 32 characters (a shorter key is refused); generate one with `openssl rand -base64 36`. |
| `IDENTITY_API_KEY_NEXT[_FILE]` | A second full-access key accepted alongside the first, to rotate the admin key without a lockout. |
| `IDENTITY_DEPLOY_KEY[_FILE]` | Optional narrow key for deploy tooling: read, register/update apps, create groups, make grants. Nothing destructive. |
| `IDENTITY_FORWARDED_ALLOW_IPS` | Peers whose `X-Forwarded-*` headers are believed (default `127.0.0.1`; behind a proxy set its address, never `*`). |
| `IDENTITY_TRUSTED_HOPS` | Proxies in front of the app for the client address used by the rate limits (default 1; 0 = the socket peer). |
| `IDENTITY_HOST` / `HOST` | Bind address (default `0.0.0.0`). `IDENTITY_ALLOW_ANONYMOUS` is honoured only on loopback, or with `IDENTITY_ALLOW_ANONYMOUS_PUBLIC=1`. |
| `IDENTITY_REFRESH_TTL_DAYS` | Refresh token lifetime, 1 to 365 days (default 30). |

## Documentation

The complete guide is [docs/GUIDE.md](docs/GUIDE.md): how Identity fits the ecosystem, architecture, install, every setting,
feature-by-feature usage, operations and troubleshooting, including the **Database** insights tab and read-only/AI access
([7.10](docs/GUIDE.md#710-database-insights-console-database), [7.11](docs/GUIDE.md#711-what-a-read-only-database-user-and-agentpgs-restricted-mcp-can-see),
[EDB and AgentPG capabilities used](docs/GUIDE.md#13b-edb-and-agentpg-capabilities-used-by-this-app)). A tutorial video script (with reproducible seed data) is in
[docs/VIDEO-SCRIPT.md](docs/VIDEO-SCRIPT.md); `docs/video/` holds the Playwright recorder that plays it.

## Security notes

See [SECURITY.md](SECURITY.md). In short: PKCE required for all, exact redirect matching, codes live 60 s and are
single-use (a wrong verifier burns the code), secrets only as hashes, signing keys and provider secrets encrypted, the SSO
cookie never opens the admin console, sign-in failures rate-limited by address and by username, strict CSP.

## Not built (yet)

Consent screens for third-party apps (every registered app is trusted by you), MFA, SAML, SCIM provisioning, `prompt=login`
re-authentication, and immediate revocation of access tokens (they live 10 minutes; refresh tokens revoke at once).

## Tests

```bash
make test-db     # needs POSTGRES_PASSWORD exported; uses a throwaway database
```
