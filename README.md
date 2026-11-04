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
| `IDENTITY_DEV_HTTP` | **Local development only, never in production.** Set to `1` to let the OAuth endpoints work over plain `http` on names such as `identity.localhost`. It takes effect only when the configured issuer (`IDENTITY_ISSUER` / `IDENTITY_PUBLIC_URL`) is `http://` on `localhost`, `127.0.0.1`, `[::1]` or `*.localhost`; with an https or non-loopback issuer it does nothing. Logged as a WARNING at start-up and shown as `insecure_transport_relaxed` in `/readyz` and the admin overview. |
| `IDENTITY_REFRESH_TTL_DAYS` | Refresh token lifetime, 1 to 365 days (default 30). |

## Sealed boot

Anything in an app's environment, config files or image is readable by whoever breaches the platform. With sealed boot, Identity is
deployed with ONE variable: `APGKIT_SEALED`, a blob encrypted (AES-256-GCM) under an operator passphrase. It holds `DATABASE_URL`,
`IDENTITY_API_KEY` and any other secret; set nothing else secret. Make it with `ecoctl seal` (agentpg-ecosystem). Identity starts
sealed: every route answers 503 except `/_seal/*`, `/healthz`, `/health` and `/livez`. The operator sends the passphrase (encrypted to
an ephemeral in-process key, `ecoctl unseal`); Identity then opens the blob, applies the migrations, opens or creates the vault with the
same passphrase (the signing keys stay wrapped under that passphrase alone; `IDENTITY_ENCRYPTION_KEY` is ignored) and serves. After a
restart it is sealed again. With no `APGKIT_SEALED` nothing changes.

## Row MACs

A database WRITE alone (no vault data key) must not forge identities, widen privileges, redirect codes or publish attacker signing keys. Every
security-relevant row carries a `mac`: an HMAC-SHA256 under a subkey of the vault data key (agentpg-kit `Vault.row_mac`) over the fields that
matter, written in the same transaction as the change.

| Table | Fields covered |
| --- | --- |
| `idp_user` | id, username, email, password_hash, status |
| `idp_federated` | provider, subject, user_id |
| `idp_membership` | user_id, group_id |
| `idp_app` | client_id, kind, secret_hash, redirect_uris, post_logout_uris, allowed_scopes, allowed_audiences, roles, default_roles |
| `idp_role_grant` | subject_type, subject_id, client_id, role |
| `signing_key` | kid, alg, public_jwk, status, retire_at |
| `oauth_code` | code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at |
| `oauth_refresh` | token_hash, family_id, client_id, user_id, scope, auth_time, expires_at, used_at, revoked_at |
| `federation_provider` | provider, client_id, client_secret_enc, enabled, mode, allowed_domains, default_groups |

Every read that feeds a sign-in or token decision (user lookup at login, client lookup, role resolution, code and refresh redemption,
signing-key selection and the published JWKS, federation settings) verifies the MAC, and a missing or wrong MAC is treated exactly like a
missing row. A refused row is logged (table and primary key only), counted in `idp_tampered_rows_total{table=...}` and audited once per row
per process (`row_mac_invalid`). With the vault locked nothing can be verified, so those lookups fail closed (token requests answer 503;
`/jwks.json` keeps serving only the set this process verified earlier, nothing after a cold start). Rotating the vault data key changes every
MAC; `identity rotate-vault-key` re-signs the rows that verified before it.

Limits:

- A copied older authentic row (with its MAC) can be replayed from a backup: the MAC proves the row was written by Identity, not that it is current.
- Deleting rows is still possible (a deleted grant, user or key simply stops existing).
- Unsigned rows are ignored, so the worst an attacker's database write can do is deny service (a user, app or key that stops working until an operator repairs it).
- Columns outside the lists above (display name, description, URLs, timestamps such as `last_login_at`) are not covered.

Existing databases: after upgrading and migrating (`002_rowmac`), run `identity adopt-rowmacs`. It asks for the admin password (or reads
`IDENTITY_ADMIN_PASSWORD_FILE`, or uses `IDENTITY_ENCRYPTION_KEY`), signs every row that has no MAC and prints the counts per table. **It trusts
the database as it is at that moment**: run it once, on a database you believe untampered. Until then those rows are ignored (nobody can sign in).
Fresh databases need nothing. After `identity reset-admin` (new vault, new data key) run it again.

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
