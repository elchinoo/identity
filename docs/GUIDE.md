# Identity: the complete guide

Identity is the OpenID Connect and OAuth 2.0 provider of the AgentPG ecosystem. One sign-in for every app, one place that says who
may do what, and one place that hands out short-lived tokens to services.

This guide is checked against the code in this repository (`src/identity`, `tests`, `Dockerfile`, CI workflow) and against the
`agentpg-kit` 0.3.0 sources it builds on. Where something is derived from reading code and was not exercised, it says so; anything
unverified is listed in [Known limitations](#16-known-limitations). The short overview is the [README](../README.md), the
security model is [SECURITY.md](../SECURITY.md).

Contents

1. [Purpose and audience](#1-purpose-and-audience)
2. [How it fits the ecosystem](#2-how-it-fits-the-ecosystem)
3. [Architecture](#3-architecture)
4. [Install](#4-install)
5. [Configuration reference](#5-configuration-reference)
6. [First-run walkthrough](#6-first-run-walkthrough)
7. [Using it, feature by feature](#7-using-it-feature-by-feature)
8. [Roles and permissions](#8-roles-and-permissions)
9. [Security notes](#9-security-notes)
10. [Operations](#10-operations)
11. [Troubleshooting](#11-troubleshooting)
12. [Testing and development](#12-testing-and-development)
13. [AIDB and AgentPG integration](#13-aidb-and-agentpg-integration)
13b. [EDB and AgentPG capabilities used by this app](#13b-edb-and-agentpg-capabilities-used-by-this-app)
14. [HTTP endpoint reference](#14-http-endpoint-reference)
15. [Data model](#15-data-model)
16. [Known limitations](#16-known-limitations)

---

## 1. Purpose and audience

**What it does.** People sign in once (local password, or Google or GitHub) and every registered app trusts the result. Each app
defines its own roles (`approver`, `viewer`, ...); administrators grant them to people directly or through groups. An app receives a
signed token that carries only the roles of that app, verifies it locally against Identity's published keys, and maps roles to its
own permissions. Services (an app calling another app, a job, an agent) get tokens with the `client_credentials` grant instead of
hand-copied shared secrets, each scoped to one target app at a time.

**Who it is for.**

| Reader | What they use it for |
|---|---|
| Fleet operator | Deploys it (usually through `ecoctl`), keeps the vault unlocked, rotates keys, adds people |
| App developer | Registers an app, points it at the issuer, verifies tokens (the kit does this in a few lines) |
| Security reviewer | Reads the model in [section 9](#9-security-notes) and the tests that pin it |
| Customer evaluating the showcase | Sees one sign-in across the whole fleet and per-app roles |

**What it is not.** It is a small provider for a showcase fleet, not a full enterprise IdP. There are no consent screens, no MFA, no
SAML, no SCIM, and access tokens cannot be revoked before they expire (10 minutes). See [section 16](#16-known-limitations).

---

## 2. How it fits the ecosystem

Everything below is read from `ecosystem/ecosystem.yaml` and `ecosystem/src/ecoctl` (the registration code), and from the kit.

### 2.1 The relationships

```mermaid
flowchart LR
  subgraph people[People]
    B[Browser]
  end
  IDP["Identity<br/>OIDC provider"]
  ECO[ecoctl]
  subgraph apps["Web apps - each has a web client"]
    TD[TrustDesk]
    PL[PagerLens]
    CP[CityPulse]
    SIM[CityPulse Simulator]
    PB[PayBroker]
    SF[ShopFront]
    GW[LLM gateway]
  end
  AG["PagerLens agent<br/>runs elsewhere"]
  B -->|"sign in: code + PKCE"| IDP
  B --> apps
  apps -->|"JWKS fetch, discovery"| IDP
  CP -->|"client_credentials: citypulse-service"| IDP
  SIM -->|"client_credentials: cpsim-service"| IDP
  AG -->|"client_credentials: pagerlens-agent-service"| IDP
  ECO -->|"admin API with the static key"| IDP
  SIM -.->|"IDENTITY_URL"| IDP
```

### 2.2 Interaction with each project

| Project | How it uses Identity | Credentials and variables | Scopes |
|---|---|---|---|
| **agentpg-kit** (`apgkit`) | Identity is built from kit blocks (config, Postgres, vault, guard middleware, metrics, local admin, the relying-party code used for Google and GitHub). The kit's `TokenVerifier`, `RelyingParty`, `TokenSource` and `from_env` are the client side of this provider. | An app turns federation on with `<PREFIX>_OIDC_ISSUER`, `<PREFIX>_OIDC_CLIENT_ID` (default: the app name), `<PREFIX>_OIDC_CLIENT_SECRET[_FILE]` (empty means a public client), `<PREFIX>_LOCAL_LOGIN` (default true: keep the local admin password as break-glass) | (none for people) |
| **ecoctl** | Provisions Identity itself, then registers every app through its admin API and creates groups and grants. Also registers its own service client `ecoctl` for `ecoctl connect`. | Identity is created with `IDENTITY_API_KEY` (generated, kept in `.ecosystem/state.json`) and `IDENTITY_ENCRYPTION_KEY` (generated). ecoctl calls the admin API with `Authorization: Bearer <that key>`, which is full access. | `ecoctl` client: `<peer>.admin` and `<app>.admin` of every `connect` pair (today `paybroker.admin`, `shopfront.admin`) |
| **TrustDesk, PagerLens, CityPulse, CityPulse Simulator, PayBroker, ShopFront, LLM gateway** | Each is registered as a **web** client whose `client_id` is its manifest key (`trustdesk`, `pagerlens`, `citypulse`, `cpsim`, `paybroker`, `shopfront`, `llmgw`). The manifest's `roles` become the app's role catalogue; the redirect URI is `https://<app>/auth/callback` and the post-logout URI `https://<app>/`, set once the real URL is known. | Per app: `<PREFIX>_OIDC_ISSUER` (the Identity URL), `<PREFIX>_OIDC_CLIENT_ID`, `<PREFIX>_OIDC_CLIENT_SECRET`. Prefix is the manifest `env_prefix` (default: the key upper-cased; `CPSIM`, `LLMGW` for the two with a different prefix). | Standard OIDC scopes `openid profile email roles` (the kit's relying party asks for these) |
| **CityPulse** | Service client `citypulse-service` calls PagerLens. | `CITYPULSE_SERVICE_CLIENT_ID`, `CITYPULSE_SERVICE_CLIENT_SECRET`, `PAGERLENS_URL` | `pagerlens.ingest` (audience `pagerlens`) |
| **CityPulse Simulator** | Service client `cpsim-service` calls CityPulse, TrustDesk, PagerLens and the LLM gateway. Also receives `IDENTITY_URL` (through `uses`), so it holds Identity's address. | `CPSIM_SERVICE_CLIENT_ID`, `CPSIM_SERVICE_CLIENT_SECRET`, `CITYPULSE_URL`, `TRUSTDESK_URL`, `PAGERLENS_URL`, `LLMGW_URL`, `IDENTITY_URL` | `citypulse.ingest`, `trustdesk.requests.write`, `pagerlens.ingest`, `llmgw.use` (one audience per token) |
| **PagerLens agent** | Registered only (`deploy: false`, `web: false`): a service client `pagerlens-agent-service` for a collector that runs next to what it watches. | `PAGERLENS_AGENT_SERVICE_CLIENT_ID/_SECRET`, `PAGERLENS_URL` | `pagerlens.ingest` |
| **PayBroker** | Web client for its console; its `paybroker.admin` scope is what `ecoctl` uses. Merchants call PayBroker with merchant keys, which Identity does not issue. | `PAYBROKER_OIDC_*` | `paybroker.read`, `paybroker.metrics`, `paybroker.admin` are exposed (declared in the manifest) |
| **ShopFront** | Web client for staff; `shopfront.admin` is used by `ecoctl connect` to push PayBroker settings. | `SHOPFRONT_OIDC_*` | `shopfront.api`, `shopfront.read`, `shopfront.metrics`, `shopfront.admin` exposed |
| **LLM gateway** | Web client for its console and `llmgw.use` exposed for the simulator. Apps' own model calls use `lg_` keys from the gateway, **not** Identity tokens. | `LLMGW_OIDC_*` | `llmgw.use`, `llmgw.read`, `llmgw.metrics` |

Rules that tie these together (enforced by Identity code, tested in `tests/test_flow.py`):

* A **scope names its target app by its prefix**: `trustdesk.requests.write` addresses the `trustdesk` audience. A service token may
  carry scopes of **one** audience only; asking for two returns `invalid_scope`.
* A service may only request scopes listed in its `allowed_scopes`, for audiences listed in `allowed_audiences` (or itself).
* An app that does not define a scope in `exposes` in the manifest is caught by `ecoctl validate`; Identity itself does not know what
  an app exposes, it only enforces what the service client was registered with.
* A user access token has `aud` = the client id of the app it was issued for and carries only that app's roles (`trustdesk:approver`).
  The kit's `AppAuth` ignores roles of other apps.

### 2.3 Access groups the manifest creates

`ecoctl apply` creates groups and role grants from the manifest's `access:` block: `ecosystem-admins` (role `admin` in every app),
`risk-team` (PayBroker `risk_manager`, PagerLens `viewer`), `support` (TrustDesk `approver`). Add people to a group in the console
and they hold those roles from their next sign-in.

---

## 3. Architecture

```mermaid
flowchart TB
  subgraph clients
    BR["Browser: /login, /apps, /admin"]
    APP["Relying app: kit TokenVerifier + RelyingParty"]
    SVC["Service: client_credentials"]
    OPS["Operator: console or admin API"]
  end
  subgraph identity["Identity process - FastAPI, uvicorn"]
    G["SecurityGuard middleware<br/>headers, CSP, 64 KB body cap, CSRF header"]
    SSO["SSO sign-in<br/>password, Google, GitHub"]
    OA["OAuth/OIDC server - Authlib<br/>StrictPKCE, scope policy, token generator"]
    ADM["Admin API /api/*<br/>users, groups, apps, grants, keys, federation, audit"]
    KEYS["keys.py<br/>RS256 signing keys"]
    VAULT["Vault - kit<br/>data key in memory"]
  end
  DB[("Postgres<br/>idp_* tables, oauth_*, signing_key,<br/>federation_provider, app_setting, web_session")]
  UP["Google / GitHub"]
  BR --> G
  APP --> G
  SVC --> G
  OPS --> G
  G --> SSO
  G --> OA
  G --> ADM
  SSO --> UP
  OA --> KEYS
  KEYS --> VAULT
  SSO --> DB
  OA --> DB
  ADM --> DB
  KEYS --> DB
  VAULT --> DB
```

How the pieces work, by module:

| Module | Role |
|---|---|
| `api.py` | The FastAPI app: health, discovery, JWKS, sign-in pages and endpoints, OAuth endpoints, operator console API, `lifespan` start-up |
| `oauth.py` | The OAuth 2.0 / OIDC server on Authlib's grants: `StrictPKCE`, `CodeGrant`, `RefreshGrant`, `ServiceGrant`, `ScopePolicy`, `TokenGenerator` (RFC 9068 JWTs), revocation and introspection endpoints |
| `keys.py` | Generates RSA-2048 keys, stores the private half encrypted under the vault, publishes the JWKS, rotates, retires |
| `users.py`, `apps.py` | People, groups, role grants; app registration and validation |
| `federation.py` | Google (OIDC) and GitHub (OAuth 2.0) sign-in and the account-mapping rules |
| `admin_api.py` | The `/api/*` operator router and its request models (`extra="forbid"` everywhere) |
| `core.py` | The singletons (database, vault, auth, rate limiter) and the console's permission map |
| `audit.py` | `idp_audit` writes, in the same transaction as the change |
| `cli.py` | `identity migrate | serve | start | reset-admin` |
| `static/` | Sign-in page, launcher, admin console (plain JS, no inline script) and the shared `/kit/` UI |

Lifecycle of a start (`identity start`): apply SQL migrations (the kit's shared tables, then `001_init.sql`, recorded in
`identity_migrations`), then serve with `uvicorn` (`proxy_headers=True`, `forwarded_allow_ips="*"`). During the application start-up
it tries to unlock the vault with the platform secret, creates the vault from the platform secret alone if none exists and a platform
secret is set, makes sure an active signing key exists (needs the vault unlocked), and prints the one-time setup code if no admin
exists yet. Any failure there (for example a sleeping database) is swallowed; everything retries on the first request.

State that lives only in memory, per process: the unlocked vault key, the decrypted signing key (re-checked against the database every
30 seconds, see [10.3](#103-rotation)), the setup code, the failed-attempt
limiters, and the cached OAuth server (and so the issuer). Everything else is in Postgres, including browser sessions.

---

## 4. Install

Requirements: Python 3.11 or newer (the image uses 3.14), a Postgres reachable by DSN with a **UTF-8 database**, and the
`agentpg-kit` package (0.2.5 or newer). No Postgres extension is required: the migration creates plain tables (the ecosystem
manifest lists `extensions: []` for Identity).

> Database encoding matters. On a database created with `SQL_ASCII`, text columns come back as `bytes` and the admin password check
> would fail with `invalid credentials` even though the right password was set. Identity now checks this: `identity start` and
> `identity migrate` stop with a message naming the encoding, and `/readyz` answers `bad-database-encoding`. Create the database with
> `ENCODING 'UTF8'`.

### 4.1 Local development with a throwaway Postgres

Option A: the repository's Compose file (needs Docker). It starts `pgvector/pgvector:pg17` on `127.0.0.1:5436`, user and database
`identity`, with the password you put in `.env`.

```bash
cp .env.example .env                 # set POSTGRES_PASSWORD (any value, local only)
docker compose up -d db
uv venv && uv pip install -e ../agentpg-kit -e ".[dev]"   # sibling checkout of the kit; or install the kit release, then this app
set -a; . ./.env; set +a
identity start                       # http://localhost:8000
```

`.env.example` already sets `DATABASE_URL=postgresql://identity:${POSTGRES_PASSWORD}@127.0.0.1:5436/identity`. The first start prints
the one-time setup code to the server log (stderr).

Option B: a native throwaway cluster, no Docker.

```bash
initdb -D /tmp/idp-pg -U identity --auth=trust -E UTF8
pg_ctl -D /tmp/idp-pg -o "-p 55436 -k /tmp -c listen_addresses=127.0.0.1" -l /tmp/idp-pg.log start
createdb -h 127.0.0.1 -p 55436 -U identity identity
export DATABASE_URL=postgresql://identity@127.0.0.1:55436/identity
export IDENTITY_PUBLIC_URL=http://localhost:8000
identity start 2> idp.log &          # the setup code is in idp.log
# clean up: pg_ctl -D /tmp/idp-pg stop && rm -rf /tmp/idp-pg
```

Set `IDENTITY_PUBLIC_URL` before the first request when you know the URL; see [issuer](#53-the-issuer-is-fixed-by-the-first-request).

### 4.2 Docker image

`Dockerfile`: `python:3.14-slim`, installs `agentpg-kit` from the GitHub release tag `v0.2.5` (build argument `KIT_URL`), then the
app; runs as the unprivileged user `app`; `HOST=0.0.0.0`, `PORT=8000`; `SSL_CERT_FILE` points at the system CA bundle (psycopg's
bundled OpenSSL does not find Debian's roots, which breaks `sslrootcert=system`); `HEALTHCHECK` calls `/healthz`;
`CMD ["identity", "start"]`. The database connection is supplied at run time, never baked in.

```bash
docker build -t identity .
docker run --rm -p 8000:8000 \
  -e DATABASE_URL=postgresql://identity:...@host:5432/identity \
  -e IDENTITY_PUBLIC_URL=https://identity.example.org \
  -e IDENTITY_ENCRYPTION_KEY="$(openssl rand -base64 48)" \
  identity
```

CI (`.github/workflows/build-image.yml`) runs `ruff check` and `pytest` against a `pgvector/pgvector:pg17` service on every push and
tag, runs `pip-audit` (non-blocking), then builds and pushes `ghcr.io/<owner>/identity` with tags `latest`, the commit SHA, and any
`v*` tag. A nightly schedule rebuilds without cache to pick up base-image updates.

### 4.3 Deploy with ecoctl (the fleet)

`ecoctl` creates Identity first: one AgentPG instance (database) and one sandbox running `ghcr.io/elchinoo/identity`, with
`IDENTITY_API_KEY` and `IDENTITY_ENCRYPTION_KEY` generated and passed as secret environment variables, auto-pause off. It then waits
for `/readyz`, makes the first request (`/.well-known/openid-configuration`) over the public URL so the issuer is pinned to it, and
registers each app. Do not hardcode the URL anywhere: it contains the sandbox id and changes when the sandbox is recreated, which is
why `ecoctl recreate identity` recreates the whole fleet.

```bash
cd ecosystem
.venv/bin/ecoctl validate
.venv/bin/ecoctl plan                      # every command and API call, secrets masked; changes nothing
.venv/bin/ecoctl apply --execute           # creates and registers; safe to run again
.venv/bin/ecoctl status                    # health of each app and drift from the identity registry
.venv/bin/ecoctl env identity --reveal     # prints IDENTITY_API_KEY (use once to bootstrap; do not paste it publicly)
```

Walk-through for a first live deployment: `ecosystem/docs/DEPLOY.md`. Identity is the one app that must never sleep (everything
signs in through it), so the manifest sets `auto_pause: false` for it.

---

## 5. Configuration reference

Verified in `core.py`, `api.py`, `cli.py`, the kit (`config.py`, `vault.py`, `auth/local.py`, `auth/authenticator.py`, `web.py`) and the
`Dockerfile`. Booleans accept `1`, `true`, `yes`, `on` (case-insensitive); anything else is false.

### 5.1 Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL`, `DB_EXTERNAL_DSN`, `PSQL_CONNECTION_STRING` | none | Postgres DSN. The first one that is set and non-empty wins, in that order. If none is set the DSN is empty and libpq falls back to `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` (which linked AgentPG sandboxes also provide). |
| `IDENTITY_PUBLIC_URL` | the first request's own address (scheme from `X-Forwarded-Proto`, host from `Host`) | The URL Identity is reached at. Used for the issuer (unless `IDENTITY_ISSUER`) and for the callback URL registered at Google and GitHub. Trailing `/` is stripped. |
| `IDENTITY_ISSUER` | `IDENTITY_PUBLIC_URL`, else the request address | The token issuer (`iss`). Wins over the public URL for tokens and discovery. Fixed for the life of the process by the first OAuth/discovery request. |
| `IDENTITY_ENCRYPTION_KEY` | none | The **platform secret** that unlocks the vault at start-up (signing keys, provider secrets). Any long random value. If the vault does not exist yet and no admin password is set, it is created from this secret alone. |
| `IDENTITY_ENCRYPTION_KEY_FILE` | `/etc/identity/encryption_key` | The same secret as a file (first line). Used only when the variable above is empty. |
| `IDENTITY_API_KEY` | none | Optional static full-access key for automation (`Authorization: Bearer <key>` on `/api/*`, or the "Use the server's API key instead" sign-in in the console). While it is set and no admin password exists, **the setup-code flow is off** (`needs_setup` is false). |
| `IDENTITY_API_KEY_FILE` | `/etc/identity/api_key` | The same key as a file. |
| `IDENTITY_API_KEY_NEXT` / `_FILE` | none | A **second full-access key**, accepted alongside `IDENTITY_API_KEY`. Rotating the admin key without data loss or a lockout: (1) set `IDENTITY_API_KEY_NEXT` to the new value and restart; (2) move every caller (ecoctl state, CI) to the new key; (3) set `IDENTITY_API_KEY` to the new value, remove `IDENTITY_API_KEY_NEXT`, restart. Nothing is stored in the database, so nothing is lost. Keys are read from the environment or the file on each request and compared in constant time. |
| `IDENTITY_DEPLOY_KEY` / `_FILE` | none | A **narrow credential for deploy tooling**. It holds `admin:read`, `apps:write`, `groups:write`, `grants:write`: list/read everything, register and update apps, create groups, make grants. It is refused (403) for: resetting a client secret, deleting apps, groups or grants, creating or changing users and passwords, signing-key rotation (graceful or emergency), federation, operator tokens and database insights. Those need the admin key, the admin password session or a `full` token. It is not a sandbox: it can change an app's redirect URIs and grant roles to existing users and groups, so keep it as secret as the admin key, just with a smaller blast radius. Today ecoctl and the Ansible recipe still use the admin key (they reset client secrets when re-registering an app); moving them to this key is a follow-up. |
| `IDENTITY_REFRESH_TTL_DAYS` | `30` | Lifetime of refresh tokens issued from now on (1 to 365; anything else is ignored and the default applies). Tokens already issued keep their stored expiry. |
| `IDENTITY_ALLOW_ANONYMOUS` | `false` | If true, every request to a protected route is treated as an administrator with full access. Never set this outside a throwaway test. |
| `HOST` | `0.0.0.0` | Bind address of `identity serve|start`. |
| `PORT` | `8000` | Bind port. The image's `HEALTHCHECK` reads `PORT`, so keep it set (the image sets it). |
| `SSL_CERT_FILE` | set by the image to `/etc/ssl/certs/ca-certificates.crt` | CA bundle for outbound and database TLS (`sslrootcert=system`). |

There is no `IDENTITY_LOCAL_LOGIN`: the local admin password is always available and never federated. There is also no private-URL
setting and no pool-size setting: Identity's outbound calls go only to Google and GitHub at fixed `https` addresses (no URL is ever taken from
configuration or a request, so there is nothing for an SSRF guard to check), and it opens one short-lived database connection per request
rather than a pool.

### 5.2 Fixed values in code

These are constants, not settings.

| Value | Where | Setting |
|---|---|---|
| Authorization code lifetime | `oauth.CODE_TTL` | 60 seconds, single use |
| Access token lifetime | `oauth.ACCESS_TTL` | 600 seconds, RS256 JWT, `typ: at+jwt` |
| ID token lifetime | `oauth.ID_TTL` | 600 seconds |
| Refresh token lifetime | `oauth.refresh_ttl()` | 30 days by default (`IDENTITY_REFRESH_TTL_DAYS`), rotated on every use |
| Signing key | `keys.py` | RSA 2048, RS256; a rotated key stays published 24 hours (`RETIRE_AFTER`); an emergency rotation removes old keys at once (below) |
| JWKS cache hint | `/jwks.json` | `Cache-Control: public, max-age=300` |
| Person (SSO) session | `start_sso` | 12 hours, cookie `idp_sso`, `HttpOnly`, `SameSite=Lax`, `Secure` over https |
| Admin session | `_admin_session` | 12 hours, cookie `idp_admin`, `HttpOnly`, `SameSite=Strict`, `Secure` over https |
| Sign-in failure limit | `core.login_limiter` | 10 failures per 300 s, per client address and per username |
| Admin sign-in/API failure limit | kit `FailureLimiter` default | 10 failures per 60 s per client address |
| Request body cap | `SecurityGuard` | 64 KiB on `/api/`, `/login`, `/oauth/` |
| Post-login return path | `core.MAX_NEXT` | 2048 characters, same-site path only |
| Upstream sign-in state | `federation.STATE_MINUTES` | 10 minutes, single use |
| Password | kit `passwords` | 12 to 256 characters, scrypt |

### 5.3 The issuer is fixed by the first request

The OAuth server object is built on the first request that needs it (discovery, authorize, token, revoke, introspect, userinfo) and
cached for the life of the process, including its issuer. If `IDENTITY_PUBLIC_URL` is unset, the first caller decides the issuer from
its `Host`. A relying app compares the issuer in the discovery document with the one it was configured with and refuses a mismatch.
So: set `IDENTITY_PUBLIC_URL` (or let `ecoctl` make the first request over the public URL) and do not change it afterwards. Changing it
means restarting Identity and re-pointing every app's `*_OIDC_ISSUER`.

### 5.4 Per-app settings (in the console, stored in the database)

Client id, kind, redirect URIs, post-logout URIs, allowed scopes, allowed audiences, roles, default roles, launcher URL, status; the
federation providers (client id, secret, mode, domains, default groups). See [section 7](#7-using-it-feature-by-feature).

---

## 6. First-run walkthrough

1. Start Identity (section 4). With no `IDENTITY_API_KEY` set, the log shows:

   ```
   === Identity first-run setup ===
   Open the app in your browser and enter this one-time code to create the admin password:
       XXXX-XXXX-XXXX
   (It changes every time the server restarts until setup is complete.)
   ```

2. Open `/admin`. Enter the setup code and choose the admin password (12 or more characters). This creates the vault (the data key is
   wrapped under the password, and also under `IDENTITY_ENCRYPTION_KEY` if you set one), generates the first signing key, and signs
   you in. `/readyz` now answers `{"status":"ready"}`.
3. **Set `IDENTITY_ENCRYPTION_KEY`** (a long random value, or a file via `IDENTITY_ENCRYPTION_KEY_FILE`) and restart, so the vault
   unlocks itself. Without it, after every restart no token can be issued until the admin signs in, and `/readyz` says `locked`.
4. If you deployed with `IDENTITY_API_KEY` (as `ecoctl` does) there is no setup code: open `/admin`, expand **Use the server's API
   key instead**, sign in with the key, then **Settings -> Admin password** to set one. Keep the key for automation.
5. **Users**: add yourself (username, e-mail, optional password of 12+ characters).
6. **Apps**: register an app (section 7.3). Copy its secret now; it is shown once.
7. **Users -> Roles** or **Groups**: give people roles in that app.
8. Point the app at Identity: `<APP>_OIDC_ISSUER=<identity url>`, `<APP>_OIDC_CLIENT_ID=<client id>`, `<APP>_OIDC_CLIENT_SECRET=<secret>`.
9. Open `/apps` as an ordinary user: the launcher lists the apps you hold a role in.

A scripted version of steps 1 to 8 against a local Identity (checked with a throwaway Postgres) is in
[VIDEO-SCRIPT.md](VIDEO-SCRIPT.md#prerequisites-and-seed-data).

---

## 7. Using it, feature by feature

There are three surfaces: the **sign-in and launcher** pages for people, the **OAuth/OIDC endpoints** for apps and services, and the
**operator console** (`/admin`, backed by `/api/*`). Identity has no MCP server and no AI features of its own.

### 7.1 Signing in (people)

* `/login` is the sign-in page: username **or** e-mail plus password, and a "Continue with Google/GitHub" button for each enabled
  provider. Failures are rate limited and answer one message for unknown user, wrong password and disabled account.
* `/apps` is the launcher: a tile for each active, non-service app with a launcher URL where you hold at least one role (a direct
  grant, a group grant, or the app's default roles). The tile lists the roles. `/` redirects to `/apps` when an SSO cookie exists, to
  `/login` otherwise.
* `POST /logout` ends the SSO session; `GET /oauth/logout` is the OIDC end-session endpoint.
* The SSO cookie identifies a person. It opens no part of `/api` (tested): a signed-in user is not an administrator.

### 7.2 Users and groups (console: Users, Groups)

* **Add a person**: username (2 to 64 characters of `a-z 0-9 . _ -`, starting with a letter or digit), e-mail (unique,
  case-insensitive), optional name, optional password (12+ characters; leave empty for someone who will use Google or GitHub), optional
  groups (comma separated, must exist).
* **Roles** opens a user: grant a role in an app (the app must define that role), see federated links, remove direct grants.
* **Disable / Enable**: a disabled person cannot sign in, and their refresh tokens are revoked at once. Their access tokens remain valid
  until they expire (at most 10 minutes).
* **Password**: set a new password for someone (also revokes their refresh tokens).
* **Delete**: removes the user, their direct grants, memberships, federated links and refresh tokens.
* **Groups**: create a group (name: lowercase letters, digits, `. _ -`), and grant a role in an app to the whole group. Deleting a
  group deletes its grants. Add a person to a group when creating them or with `POST /api/users/{id}/groups`.

### 7.3 Apps (console: Apps)

Register an app with:

| Field | Rule |
|---|---|
| Client id | 2 to 40 characters of `a-z 0-9 -`; also the **role namespace** in tokens (`<client id>:<role>`) |
| Kind | `web` (server-side, has a secret), `public` (PKCE only, no secret; token endpoint auth method `none`), `service` (machine to machine, no users, `client_credentials` only) |
| Redirect URIs | exact strings, at most 20: `https`, or `http` on `localhost`, `127.0.0.1`, `::1` or `*.localhost`; no wildcard, fragment or credentials; required for `web` and `public` |
| Post-logout URIs | same rules; where `/oauth/logout` may send the browser back |
| Roles | the roles the app defines (name `a-z 0-9 . _ -`, at most 40 characters, at most 40 roles) |
| Default roles | granted to **every active user**; must be among the app's roles |
| Allowed scopes | scopes it may request beyond `openid profile email roles offline_access` (regex `[a-z0-9][a-z0-9._:-]{0,59}`) |
| Allowed audiences | for a service: other apps it may obtain tokens for (client ids) |
| App URL | shown in the launcher |

The secret (`cs_...`) is returned once and stored only as a SHA-256 hash. **New secret** issues another and invalidates the old one
immediately; a public client has none. **Disable** blocks the app (no new tokens) and revokes its refresh tokens; **Delete** removes
the app, its grants, codes and refresh tokens. Removing a role from an app's catalogue deletes its grants. The console form does
not expose an app description field (the API does).

Connecting an app is three variables (`<PREFIX>_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET[_FILE]`); with the kit that is all:

```python
from apgkit.auth import AppAuth, Authenticator, LocalAuth, from_env
fed = from_env("MYAPP", "myapp")                    # reads MYAPP_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET
app_auth = AppAuth("myapp", fed.client_id, role_permissions={"admin": frozenset({"*"})})
# Authenticator(..., verifier=fed.verifier) accepts Identity's tokens; fed.rp starts the browser sign-in
```

### 7.4 The OAuth 2.0 and OpenID Connect surface

| Endpoint | Behaviour |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery: issuer, endpoints, `response_types_supported: [code]`, grants `authorization_code`, `refresh_token`, `client_credentials`, `id_token_signing_alg_values_supported: [RS256]`, `code_challenge_methods_supported: [S256]`, token auth methods `client_secret_basic`, `client_secret_post`, `none`, scopes and claims |
| `GET /jwks.json` | Public keys of the active and retiring signing keys; never private material |
| `GET /oauth/authorize` | Authorization code request. An unknown client or redirect URI gets an error page, never a redirect. No SSO session: redirect to `/login?next=...`. |
| `POST /oauth/token` | `authorization_code`, `refresh_token`, `client_credentials`. Answers `503 temporarily_unavailable` with `Retry-After: 30` if tokens cannot be signed (vault locked). |
| `GET/POST /oauth/userinfo` | Bearer user access token; returns `sub`, `name`, `email`, `roles` (service tokens are refused) |
| `POST /oauth/revoke` | Revokes a **refresh** token and its whole family |
| `POST /oauth/introspect` | For refresh tokens of the calling client (confidential clients only). By code reading, an access token is not found there and reports inactive: verify access tokens locally against the JWKS. |
| `GET /oauth/logout` | RP-initiated logout: ends the SSO session; returns to `post_logout_redirect_uri` only if that exact URI is registered for the client (given as `client_id`, or derived from `id_token_hint`), appending `state` |

What the strictness adds on top of Authlib (each pinned by a test in `tests/test_flow.py`):

* **PKCE is mandatory for every client**, S256 only; a missing challenge, `plain`, or a missing or wrong `code_verifier` is refused,
  and a wrong verifier burns the code.
* **Redirect URIs match exactly.** Codes are bound to client, redirect URI and challenge.
* **Scopes a client may not request are refused**, not trimmed. A service token carries scopes of one audience app only.
* **Refresh tokens** (`rt_...`) are issued only when `offline_access` is requested, rotate on every use, and replaying a used one
  revokes the whole family. They are stored hashed.
* **Access tokens** carry `iss`, `exp`, `iat`, `client_id`, `jti`, `scope`, `sub`, `aud`. For a person: `aud` is the app's client id,
  plus `sub_type: "user"`, `name`, `email`, and `roles` (only that app's, namespaced). For a service: `sub` is the client id,
  `aud` is the target app (from the scope prefix), `sub_type: "service"`, `client_name`. ID tokens carry `sub`, and `name` and
  `preferred_username` (scope `profile`), `email` (scope `email`), `roles` (scope `roles`), plus `nonce`, `auth_time`.

Minimal service call (the `notes-worker` client built in the [video script](VIDEO-SCRIPT.md)):

```bash
curl -s -u notes-worker:"$SECRET" -d grant_type=client_credentials -d scope=notes.write "$IDP/oauth/token"
# {"token_type":"Bearer","access_token":"...","expires_in":600,"scope":"notes.write"}
```

The kit's `TokenSource` does this with caching; it also sends an `audience` parameter, which Identity ignores (the audience comes from
the scope prefix).

### 7.5 Federation (console: Federation)

Google (OpenID Connect, scopes `openid email profile`) and GitHub (OAuth 2.0, scopes `read:user user:email`, with PKCE). Register at
the provider an OAuth app whose callback URL is `<identity url>/login/google/callback` or `.../login/github/callback` (the console
prints the exact URL for the address you are on), then enter client id and secret. The secret is stored encrypted under the vault
and is never returned by the API.

Account mapping, strictest first (`federation.resolve`, tested in `tests/test_federation.py`):

1. An identity already linked (provider and subject) signs in as its user.
2. A **verified** e-mail that matches an existing user links to that user. An unverified e-mail never links. For GitHub, only the
   primary verified address counts.
3. Only in `open` mode, and only for e-mail domains on the allow-list, a new passwordless user is created and put in the provider's
   default groups. `open` requires at least one domain.
4. Otherwise the person is refused. The default mode is `invite_only`: an administrator creates the user first.

A disabled user is refused whatever the provider says. Removing a provider deletes its links. A provider can be disabled without
removing it. I did not exercise the live Google or GitHub round trip for this guide; the tests replace the HTTP transport.

### 7.6 Signing keys (console: Keys)

RS256 keys are generated here, stored encrypted, published at `/jwks.json`. **Rotate key** creates a new active key (needs the vault
unlocked, otherwise `423`); the old key becomes `retiring` and stays published for 24 hours so existing tokens verify, then is
`retired` and dropped. Apps refetch the JWKS when they see an unknown `kid`. Rotation is recorded in the audit trail.

### 7.7 Audit (console: Audit)

Every change writes a row in `idp_audit` in the same transaction: actor, action, target, detail. Actions seen in code: `login_failed`,
`login_federated`, `authorize`, `user_created`, `user_updated`, `password_reset`, `user_deleted`, `group_created`, `group_deleted`,
`group_member_added`, `group_member_removed`, `app_registered`, `app_updated`, `app_secret_rotated`, `app_deleted`, `role_granted`,
`role_revoked`, `signing_key_rotated`, `signing_key_emergency_rotated`, `federation_configured`, `federation_removed`. The API returns the latest 1 to 500 rows
(default 200). Operator-token actions are logged under the token's name, the admin password session as `admin`, the static key as `api key`.

### 7.8 Settings (console: Settings)

Change the admin password (also signs the admin out everywhere and re-wraps the vault), and create **operator tokens** (`idt_...`,
shown once, revocable): `read` (look, never change), `metrics` (scrape `/metrics`), `full`.

### 7.9 Operator API

Every console action is a call under `/api` (table in [section 14](#14-http-endpoint-reference)). From automation, send
`Authorization: Bearer <IDENTITY_API_KEY or an idt_ token>`; no CSRF header is needed with a bearer credential. Browser writes with a
cookie must send the header `X-Identity-CSRF: 1`. This is how `ecoctl` registers apps, patches redirect URIs and creates groups and
grants, idempotently.

### 7.10 Database insights (console: Database)

The **Database** tab (`GET /api/insights?order=total|mean|calls&limit=N`, full admin only: statement text shows table names and the
workload's shape) mounts the kit's `initInsights` panel. It shows what EDB's extensions on the AgentPG instance know: the slowest and
most called statements (`edb_stat_monitor`, `pg_stat_statements` as a fallback), `edb_pg_tuner` configuration recommendations and
`query_advisor` index hints. On a database without them (plain Postgres, a missing grant) every part says "Not available on this
database." with the reason; the route still answers `200`. A read-scope operator token gets `403` here. `/metrics` also exports
`db_insights_available`, `db_insights_top_query_mean_seconds{queryid}`, `db_insights_statement_calls` and
`db_insights_tuner_recommendations` (cached 30 s) so PagerLens can watch Identity's own database. Not verified here: the EDB extensions are
not installed on the local test Postgres, so only the degraded path ran; the populated path is covered by the kit's tests.

### 7.11 What a read-only database user and AgentPG's restricted MCP can see

Applied by `src/identity/hardening.py` after every migration (`identity migrate` and `identity start`, via `migrate.run(after_migrate=...)`),
using the kit's `apgkit.masking`. It acts on the group role `a1p_readonly` (members: users from `agentpg db-users create --permission read`;
the restricted MCP server of `agentpg mcp serve` runs as such a user). Where the role does not exist (plain Postgres) it does nothing.

| Table | A read-only user gets |
|---|---|
| `idp_user` | `permission denied`; use `idp_user_masked`: id, username as `a***`, email `***@domain`, name `A***`, status, dates. **No password hash.** |
| `idp_federated` | `permission denied`; `idp_federated_masked` (subject hashed, email masked) |
| `idp_app` | `permission denied`; `idp_app_masked`: everything except `secret_hash` |
| **`signing_key`** | **`permission denied`. This is the most sensitive table of the whole fleet** (encrypted private keys that sign every token): a test logs in as a real read-only role and proves it cannot read it. |
| `oauth_code`, `oauth_refresh`, `federation_provider`, `app_setting` (admin password hash, vault store), `web_session`, `api_token`, `oidc_login` | `permission denied` |
| `idp_group`, `idp_membership`, `idp_role_grant`, `idp_audit`, `identity_migrations` | readable (ids, role names, audit text; audit targets contain usernames, so treat the audit trail as internal) |

**Durability.** The hook runs at startup, but grants made later reopen tables: `agentpg db-users create` and AgentPG's default privileges give `a1p_readonly` SELECT on base tables again at any time, including `signing_key`. The app therefore re-asserts every 5 minutes (`masking.reassert_forever` in the lifespan, with `hardening.DENY`: the masked base tables plus every denied table, `signing_key` first). A grant stays readable for up to one interval. Drift shows in the gauge `masking_drift_tables` (alert on `> 0`) and in `masking` of `/readyz` (`last_ok`, `drift`, `ok`); drift never makes `/readyz` fail.

Limits: only the table owner can REVOKE (the hook checks and logs a warning if the revoke did not take); default privileges re-grant
SELECT on every NEW table, so a table added by a later migration is readable until it is added to `MASKED_VIEWS` or `DENIED_TABLES`
(a test fails if a column named like a hash, secret, token, password or private key is readable). It does not restrict the app's own owner
connection, `a1p_readwrite` members, or the hosted MCP endpoint reached with `agentpg token` (that session is read-write, see
`ecosystem/docs/06`). Hash masking is short and unsalted.

---

## 8. Roles and permissions

There are two separate permission worlds.

**A. Roles Identity manages for other apps.** Defined per app (the app's `roles` list), granted to users or groups, delivered in the
`roles` claim as `<client id>:<role>`. What a role allows is decided inside that app. See the manifest for the fleet's roles
(`admin`, `approver`, `viewer`, `responder`, `operator`, `risk_manager`, `analyst`, `staff`).

**B. Who may operate Identity itself.** Defined in `core.APP_AUTH`:

| Credential | Permissions | Notes |
|---|---|---|
| Local admin (password, session cookie `idp_admin`) | everything (`*`) | Always available, never federated; unlocks the vault on sign-in |
| Static key `IDENTITY_API_KEY` (bearer or console key sign-in) | everything (`*`) | Sign-in with the key also tries to unlock the vault with the platform secret |
| Operator token `full` | everything (`*`) | |
| Operator token `read` | `admin:read` | All `GET` endpoints under `/api` except tokens (`/api/tokens` needs `*`) |
| Operator token `metrics` | `metrics:scrape` | `GET /metrics` only |
| A person signed in at `/login` | none | The SSO cookie opens nothing under `/api` |

There is deliberately no role for a person: Identity does not verify federated tokens for its own console, so a role such as `auditor`
could not be held by any credential. Give a colleague read-only access with an operator token of scope `read`.

---

## 9. Security notes

The model is in [SECURITY.md](../SECURITY.md); the points an operator should act on:

* **Treat Identity as the most sensitive service in the fleet.** Restrict who can reach `/admin` (network policy or a proxy rule), back
  up its database, keep `IDENTITY_ENCRYPTION_KEY` away from the database host.
* **Secrets** are shown once and stored hashed (client secrets, operator tokens, sessions). The admin password is scrypt. Signing
  keys and provider secrets are Fernet-encrypted with a data key that is wrapped under the admin password and, optionally, the
  platform secret.
* **Tokens**: access tokens are short (10 min) because they cannot be revoked earlier. Disabling a user or app, or resetting a password,
  revokes refresh tokens immediately; a short window of valid access tokens remains.
* **Never** set `IDENTITY_ALLOW_ANONYMOUS` outside a test. **Never** commit `IDENTITY_API_KEY`, client secrets or the encryption key
  (`.gitignore` covers `.env`, `api_key`, `*.key`, `*.pem`).
* **Browser protections**: strict CSP (no inline script or style), `X-Frame-Options: DENY`, `no-referrer`, `no-store` (set by the
  kit's middleware), CSRF header required for cookie-authenticated writes under `/api/` and `/login`, 64 KiB body cap.
* **Open redirects**: after sign-in only a same-site path is accepted (`core.safe_next`); `/oauth/logout` returns only to
  registered URIs.
* **Federation**: PKCE, state and nonce; unverified e-mail never links; `open` needs a domain allow-list.
* **Rate limits and sessions are per process.** Running several replicas multiplies the failure budget (see limitations).
* Report vulnerabilities privately (GitHub Security tab).

---

## 10. Operations

### 10.1 Health and metrics

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | `{"status":"ok","version":...}`; does not touch the database. Used by the image's `HEALTHCHECK`. |
| `GET /readyz` | `200 {"status":"ready"}` when the database answers and a token could be signed now. `503 {"status":"locked", ...}` when there is no readable signing key (vault locked). `503 {"status":"waking-database"}` when the database cannot be reached. `503 {"status":"bad-database-encoding", ...}` when the database is not UTF-8 (the same check stops `identity start` and `identity migrate` with a message and exit code 1). |
| `GET /metrics` | Prometheus text; needs an operator token with scope `metrics` (or `full`) or the static key. Families: `http_requests_total`, `http_request_duration_seconds`, `app_info`, `process_*`. `db_up{app="identity"}` is `1` when a database connection and a trivial query work at scrape time and `0` otherwise (the scrape itself still answers). Also `db_insights_*` (see [7.10](#710-database-insights-console-database)). |

### 10.2 Backup and restore

Everything durable is in the Postgres database. Back it up with your usual tools (on AgentPG, the instance tools). A restore is only
useful together with the **vault key material**: the signing keys are encrypted with a data key wrapped under the admin password and/or
`IDENTITY_ENCRYPTION_KEY`. Keep a copy of `IDENTITY_ENCRYPTION_KEY` (for the fleet: `.ecosystem/state.json`) separately from the database
backup. Restoring the database with a different or missing platform secret leaves the vault locked until the admin signs in with the
password.

### 10.3 Rotation

| What | How | Effect |
|---|---|---|
| Signing key | Console **Keys -> Rotate key**, or `POST /api/keys/rotate` | New tokens use the new key; the old key stays in the JWKS 24 hours. The process that handled the call switches at once; other processes (replicas) switch within 30 seconds (`keys.CACHE_TTL`) |
| App client secret | **Apps -> New secret** (or `POST /api/apps/{id}/secret`) | Old secret stops at once; update the app's environment and restart it. For the fleet: `ecoctl apply --execute --rotate`, then recreate the sandboxes whose environment changed |
| Admin password | **Settings -> Admin password** | Signs out all local admin sessions; the vault is re-wrapped |
| Operator token | **Settings**: create a new one, revoke the old | |
| `IDENTITY_ENCRYPTION_KEY` | No rotate command exists. By code reading, the vault wraps a platform secret only when none was wrapped before (on password unlock); a **changed** secret is not re-wrapped, so the old one keeps unlocking and the new one does not. Treat the value as permanent for a database. | See limitations |

### 10.4 The vault and unlocking

State is visible at `GET /api/overview` (`vault.initialized`, `unlocked`, `auto_unlock`) and as a banner in the console. Unlock paths:
set `IDENTITY_ENCRYPTION_KEY` (automatic at start), sign in as admin with the password, or `POST /api/vault/unlock`.
While locked: `/readyz` is 503, `POST /oauth/token` answers `503 temporarily_unavailable`, but `/jwks.json` still serves, so tokens already
issued keep verifying.

### 10.5 Recovery: `identity reset-admin`

Run it where the server's environment is (for AgentPG: `agentpg sandbox console <sandbox-id>`, then `identity reset-admin`). It
forgets the admin password and the vault, **deletes every signing key**, **disables every federation provider** (their secrets become
unreadable), and signs everyone out of the admin console. The setup-code flow is active again after a restart. Because the signing
keys are gone, tokens issued before it no longer verify and every app's users must sign in again. Use it only when the password and the
platform secret are both lost.

### 10.6 Upgrades

Migrations are idempotent and run at every start (`identity migrate` runs them alone). For the fleet, CI pushes `:latest` and
`ecoctl recreate identity` recreates the sandbox with the same database and secrets; because the URL changes, every deployed app is
recreated too.

### 10.7 Logs

Plain stdout/stderr (uvicorn access log, the setup banner, "database not reachable (attempt n/m)" lines while a sleeping database
wakes). `agentpg sandbox logs <sandbox-id>` for a sandbox. Request bodies and secrets are not logged by the app.

---

## 11. Troubleshooting

| Symptom | Likely cause | What to check or do |
|---|---|---|
| `/readyz` says `locked`; token endpoint returns `503 temporarily_unavailable` | Vault locked: `IDENTITY_ENCRYPTION_KEY` unset, wrong, or the database was replaced | Set the same key and restart, or sign in at `/admin` with the admin password (unlocks) |
| `/readyz` says `waking-database` | Database unreachable or scaled to zero | Wait a few seconds; check the DSN; the app retries |
| API calls return `503 database unavailable ... retry` | Same as above | Retry |
| `/readyz` says `bad-database-encoding`, or `identity start` stops with "the database encoding is SQL_ASCII" | Database is not UTF-8 (text would come back as bytes and the admin password check would fail) | Recreate the database with `ENCODING 'UTF8'` (`CREATE DATABASE identity ENCODING 'UTF8' TEMPLATE template0`) |
| No setup code in the log | `IDENTITY_API_KEY` is set (setup flow off), or an admin already exists | Sign in with the API key, or `identity reset-admin` |
| `/login` returns 429 | 10 failures in 5 minutes for that address or username | Wait; the limiter is in memory (restart clears it) |
| `/api/*` returns 403 `missing CSRF header` | Cookie-authenticated write without `X-Identity-CSRF` | Add the header, or use a bearer credential |
| `/api/*` returns 403 "lacks 'admin:read'" / `'*'` | The credential is an SSO person, or a `metrics`/`read` token on a write | Use the admin session, the static key or a `full` token |
| App gets an "error page" at `/oauth/authorize` | Unknown client id, disabled app, or redirect URI not an exact match | Compare the app's registered URIs with what it sends (exact string); `ecoctl status` shows drift |
| `invalid_request: Missing 'code_challenge'` or `... must be S256` | Client does not use PKCE S256 | Enable PKCE (the kit does) |
| `invalid_scope` | A scope the client may not request, or a service asking for two audiences | Add to `allowed_scopes`/`allowed_audiences`, request one audience per token |
| `invalid_client` / 401 at the token endpoint | Wrong or rotated secret; a `public` client sending a secret, or a `web` client using `none` | Re-issue the secret; check the auth method for the kind |
| Relying app: issuer mismatch | The first request fixed a different issuer than the app's `*_OIDC_ISSUER` | Set `IDENTITY_PUBLIC_URL`, restart Identity, fix the app setting |
| New key not honoured by some replica | Each process caches the signing key and re-checks the database every 30 seconds | Wait up to 30 seconds after a rotation |
| Google/GitHub sign-in fails with "no account for this identity" | `invite_only` and no user with that verified e-mail | Create the user first, or use `open` with a domain list |
| Sign-in loop on a very long return URL | Old image limited the return path to 300 characters | Fixed (limit 2048, tested); update the image |

---

## 12. Testing and development

```bash
uv venv && uv pip install -e ../agentpg-kit -e ".[dev]"
make lint                         # ruff check src tests
make test                         # pytest; database tests are skipped unless TEST_DATABASE_URL is set
TEST_DATABASE_URL=postgresql://identity:...@127.0.0.1:5436/identity_test make test
make test-db                      # drops and recreates identity_test in the Compose db, then runs pytest
```

* The database tests **drop and recreate the `public` schema** of the database in `TEST_DATABASE_URL`. Point it only at a throwaway
  database.
* `make test-db` needs `POSTGRES_PASSWORD` exported and the Compose `db` up. The Compose file, the Makefile command and its comment all use port 5436.
* 53 tests (45 + `test_hardening.py`: kit version, insights route and degradation, metrics, read-only role cannot read `signing_key` or any secret table, masked views): `test_flow.py` (discovery, code flow with PKCE, roles per audience, group grants, refresh rotation and reuse, revocation,
  introspection, disabled user or app, client credentials, public clients, userinfo and logout, key rotation, a rotation made by another replica, long return URLs),
  `test_admin.py` (admin API protection and CSRF, operator token scopes, app registration rules, user rules, launcher, locked vault,
  platform-secret start, `db_up`, a non-UTF-8 database), `test_federation.py` (mapping rules with a replaced HTTP transport), `test_static.py` (no native dialogs;
  accessibility guards). On a local UTF-8 Postgres all 53 pass and `ruff` is clean.
* Style: line length 110, rules `E F I B UP` (see `pyproject.toml`). Code is small and commented where a reason is not obvious.

To develop against the sibling kit, `tool.uv.sources` points `agentpg-kit` at `../agentpg-kit` (editable). Images install the published
tag instead.

---

## 13. AIDB and AgentPG integration

**AgentPG (today).** Identity runs as an AgentPG sandbox on its own instance: one container, one Postgres database, public HTTPS in
front. The code is written for that platform:

* Connections retry with backoff while a scaled-to-zero database wakes; request paths turn that into `503` with a retry message, and
  `/readyz` reports `waking-database`.
* `X-Forwarded-Proto` and `X-Forwarded-For` from the platform proxy are honoured (`proxy_headers=True`), so cookies are `Secure` and URLs are
  `https`.
* The vault can start unattended from `IDENTITY_ENCRYPTION_KEY` alone, which is what lets `ecoctl` deploy it with no human present.
* `auto_pause: false` in the manifest, because every sign-in depends on it.
* The `identity start` failure message tells you to run `agentpg extensions create <instance-id> pgcrypto` if a migration mentions an extension;
  no current migration needs one.

**AIDB (today).** None. Identity does not use AIDB, pgvector or any model: its tables are plain relational tables, it has no MCP server, and
it makes no LLM calls. The ecosystem's AIDB design (`ecosystem/docs/03-aidb-integration.md`, a proposal, not an implementation) says
AIDB does not replace Identity, and that AIDB's own MCP endpoint authenticates with Postgres roles, not OIDC.

**Planned (from that design, not built).** Map Identity groups to Postgres roles through `ecoctl` provisioning, so an AIDB agent or MCP
client runs as a role with only the grants it needs. That would be provisioning code in `ecoctl`; nothing in Identity changes for it
today. Open items in the showcase plan for Identity: MFA, consent screens, access-token revocation and SAML, decide to build or state as
non-goals.

---

## 13b. EDB and AgentPG capabilities used by this app

| Capability | How Identity uses it |
|---|---|
| EDB `edb_stat_monitor`, `edb_pg_tuner`, `query_advisor` (via `pg_stat_statements` fallback) | **Database** tab and `GET /api/insights`; `db_insights_*` gauges on `/metrics` ([7.10](#710-database-insights-console-database)). Degrades to "not available" on plain Postgres. |
| AgentPG read-only role `a1p_readonly`, `agentpg db-users`, restricted MCP (`agentpg mcp serve`) | Masked views for personal data, REVOKE on secret tables including the signing keys ([7.11](#711-what-a-read-only-database-user-and-agentpgs-restricted-mcp-can-see)). Database-enforced, with no `data_redaction` extension. |
| AgentPG sandbox, instance, environment injection, scale-to-zero wake | Deployment ([section 13](#13-aidb-and-agentpg-integration)) |
| Not used | AIDB (role grants missing on the platform), pgvector, PostGIS |

---

## 14. HTTP endpoint reference

Public (no credential):

| Method and path | Purpose |
|---|---|
| `GET /healthz`, `GET /readyz` | Health and readiness |
| `GET /.well-known/openid-configuration`, `GET /jwks.json` | Discovery and keys |
| `GET /login`, `POST /login`, `GET /api/login-options` | Sign-in page, local sign-in, enabled providers |
| `GET /login/{provider}`, `GET /login/{provider}/callback` | Start and finish Google or GitHub sign-in |
| `POST /logout` | End the SSO session |
| `GET /apps`, `GET /api/my-apps` | Launcher page and its data (needs the SSO cookie) |
| `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke`, `POST /oauth/introspect`, `GET|POST /oauth/userinfo`, `GET /oauth/logout` | OAuth 2.0 / OIDC |
| `GET /`, `GET /admin` | Redirect, console page |
| `GET /api/session`, `POST /api/setup`, `POST /api/login`, `POST /api/logout` | Console bootstrap and admin sign-in (`/api/login` takes `{"password": ...}` or `{"api_key": ...}`) |

Admin (full access `*` for writes, `admin:read` for the `GET`s):

| Area | Endpoints |
|---|---|
| Vault and password | `POST /api/vault/unlock`, `POST /api/admin-password` |
| Operator tokens | `GET|POST /api/tokens`, `DELETE /api/tokens/{id}` (need `*`) |
| Overview | `GET /api/overview` |
| Users | `GET|POST /api/users`, `GET|PATCH|DELETE /api/users/{id}`, `PUT /api/users/{id}/password`, `POST /api/users/{id}/groups`, `DELETE /api/users/{id}/groups/{group}` |
| Groups | `GET|POST /api/groups`, `DELETE /api/groups/{name}` |
| Apps | `GET|POST /api/apps`, `GET|PATCH|DELETE /api/apps/{client_id}`, `POST /api/apps/{client_id}/secret` |
| Grants | `GET|POST /api/grants` (`?client_id=`), `DELETE /api/grants/{id}`; a grant body is `{subject_type: user|group, subject: <user id or group name>, client_id, role}` |
| Keys | `GET /api/keys`, `POST /api/keys/rotate` |
| Federation | `GET /api/federation`, `PUT|DELETE /api/federation/{provider}` |
| Audit | `GET /api/audit?limit=` |
| Metrics | `GET /metrics` (scope `metrics:scrape`) |

OpenAPI/Swagger pages are disabled (`docs_url`, `redoc_url`, `openapi_url` are `None`).

---

## 15. Data model

Created by `src/identity/migrations/001_init.sql` plus the kit's shared tables (`app_setting`, `web_session`, `api_token`, `oidc_login`).

| Table | Holds |
|---|---|
| `idp_user` | People: id `usr_...`, username, e-mail (unique, lower-cased), name, scrypt password hash (null for federated-only), status, last login |
| `idp_federated` | A person's account at an upstream provider (provider, subject, user) |
| `idp_group`, `idp_membership` | Groups and who is in them |
| `idp_app` | Registered apps: kind, secret hash, URIs, allowed scopes and audiences, role catalogue (jsonb), default roles, URL, status |
| `idp_role_grant` | (subject type user or group, subject id, app, role); unique |
| `oauth_code` | Authorization codes (hash, client, user, redirect URI, challenge, expiry) |
| `oauth_refresh` | Refresh tokens (hash, family, client, user, scope, used and revoked times) |
| `signing_key` | kid, algorithm, **encrypted** private key, public JWK, status `active/retiring/retired` |
| `federation_provider` | Google and GitHub settings; the secret is encrypted |
| `idp_audit` | Audit trail |
| `idp_user_masked`, `idp_federated_masked`, `idp_app_masked` | Views for the read-only role (created after each migration by `hardening.py`, not by a migration file) |
| `app_setting` | Kit key/value: admin password hash and the vault's wrapped key and salts |
| `web_session` | Admin and SSO sessions (only the SHA-256 of the cookie) |
| `api_token` | Operator tokens (hash and prefix) |
| `oidc_login` | Pending upstream sign-ins (state, verifier, nonce, return path) |
| `identity_migrations` | Applied migration names |

Expired authorization codes are not purged by a job (they are ignored when expired); expired sessions are removed when a new session
is created; stale upstream sign-in states are removed when a new one starts.

---

## 16. Known limitations

Stated by the project:

* No consent screens (every registered app is trusted), no MFA, no SAML, no SCIM provisioning, no `prompt=login` re-authentication.
* Access tokens cannot be revoked before they expire (10 minutes); refresh tokens revoke at once.
* One signing algorithm (RS256). The schema allows `ES256` but no code generates it.
* Failed-attempt limiters are per process (sessions themselves are in the database).

Found while writing this guide (from code reading unless noted; several earlier findings are fixed and no longer listed):

* The unlocked vault key is per process (the signing-key cache re-checks the database every 30 seconds, so replicas follow a rotation
  within that time; tested with a simulated second process, not with real replicas). The fleet runs one process per sandbox.
* The console is operated only by the local admin password, the static key, or operator tokens: there is no role for a federated person.
* Introspection answers only for refresh tokens, and revocation only revokes refresh families; there is no access-token introspection
  (by code reading).
* The kit's `TokenSource` sends an `audience` parameter that Identity ignores.
* No procedure to change `IDENTITY_ENCRYPTION_KEY` in place (see section 10.3); `reset-admin` is destructive for signing keys and provider secrets.
* No purge job for expired authorization codes and old refresh-token rows.
* `GET /readyz` and `GET /healthz` are unauthenticated by design.
* Not exercised for this guide: the live Google and GitHub round trip, `ecoctl apply` against AgentPG, multi-replica behaviour, and
  running the container image (Docker was not available). The local flow (setup, seed, app registration, code flow with PKCE through a
  small relying party, `client_credentials`, `/metrics`, the test suite) was run against a throwaway local Postgres.

## Emergency key rotation

Use it when a signing key may have been exposed, or someone could have written to the `signing_key` table. The graceful rotation
(console **Rotate key**, `POST /api/keys/rotate`, `identity rotate-keys`) keeps the old key published for 24 hours so nothing breaks;
the emergency one does not wait.

* API: `POST /api/keys/emergency-rotate` with `{"confirm": true, "reason": "..."}` (full admin only; the deploy key and `read` tokens get 403).
* CLI, on the host or in the container, with `DATABASE_URL` and `IDENTITY_ENCRYPTION_KEY` (or `_FILE`) set: `identity rotate-keys --emergency --yes --reason "..."`.
  Without `--emergency` the same command does the graceful rotation.

In one transaction it: creates a new active key; **deletes every earlier key** (private half included), so `/jwks.json` lists only the new
key at once; revokes every refresh token; drops pending authorization codes; ends every SSO (person) session; keeps the operator
(admin console) sessions; writes a `signing_key_emergency_rotated` audit row listing the removed kids and the counts.

What bites when: Identity itself (userinfo, introspection, logout hints) refuses old access tokens immediately. Other Identity replicas
follow within 30 seconds. An app verifier trusts the JWKS it fetched for at most `<PREFIX>_OIDC_JWKS_TTL` (5 minutes by default, capped at one hour; the kit release after 0.3.1), so old tokens stop working there within
that time; `/jwks.json` also carries `Cache-Control: max-age=300`, so budget up to about ten minutes in the worst case with any shared cache in front. Sessions
that apps keep in their own databases (`web_session`) are not touched by Identity; they end by expiry (12 hours) or by clearing that table in the app.
People sign in again; services refetch tokens on their own. Rotate the admin key (`IDENTITY_API_KEY_NEXT`) and client secrets too if they may be exposed.
