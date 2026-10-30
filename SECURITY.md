# Security policy

Report vulnerabilities privately (GitHub: Security tab, "Report a vulnerability"); do not open a public issue.

## Model

- **PKCE is mandatory** for every client, S256 only; a missing or wrong verifier is refused and burns the code. Authlib's own
  extension only requires it for public clients, so a subclass enforces it for all.
- **Redirect URIs match exactly** (never a prefix or pattern); an unknown client or URI gets an error page, never a redirect.
- Authorization codes: 60 seconds, single-use, bound to client, redirect URI and challenge. Refresh tokens: opaque, hashed
  at rest, rotated on use, a replayed one revokes its whole family; disabling a user, resetting a password or disabling an
  app revokes them at once. Access tokens: RS256 JWTs (RFC 9068, `kid` in the header), 10 minutes.
- Scopes a client may not request are refused (not trimmed); a service token carries scopes of one audience app only.
- Client secrets, operator tokens and sessions are stored as hashes; the secret is shown once. The admin password is scrypt.
- Signing keys and upstream provider secrets are encrypted with the vault key (wrapped under the admin password and,
  optionally, a platform secret). The JWKS never contains private material.
- The SSO cookie (people) and the admin cookie are different cookies; the SSO cookie opens nothing under `/api`.
- Upstream sign-in: PKCE and state/nonce; an unverified e-mail never links an account; open sign-up needs a domain allow-list.
- Sign-in failures are rate limited per address and per username. Strict CSP, no inline script, CSRF header on browser writes.

## Limits

Grants made after startup (`agentpg db-users create`, default privileges) reopen tables to the read-only database role, `signing_key` included; the app re-asserts the REVOKEs every 5 minutes (gauge `masking_drift_tables`, `masking` in `/readyz`), so a table can be readable for up to one interval.

Stored secrets are bound to their row, and the vault data key can be replaced at any time (`identity rotate-vault-key --yes`, or `POST /api/vault/rotate-key`, both needing the admin password); restart other replicas afterwards. Federated sign-in is tied to the browser that started it by a single-use binding cookie; the static admin key must be at least 32 characters; `IDENTITY_ALLOW_ANONYMOUS` works only on a loopback bind address; set `IDENTITY_FORWARDED_ALLOW_IPS` to the proxy's address (never `*`).

Rate limits and sessions are per process. Access tokens cannot be revoked before they expire, but an emergency key rotation (`identity rotate-keys --emergency --yes`, or `POST /api/keys/emergency-rotate`) makes every token signed by an earlier key unverifiable once the apps' JWKS cache (5 minutes by default) refreshes, and revokes all refresh tokens and SSO sessions. One signing algorithm (RS256).
There is no MFA. Treat the identity provider as the most sensitive service in the fleet: restrict the admin console,
back up the database, and keep `IDENTITY_ENCRYPTION_KEY` out of the database host.
