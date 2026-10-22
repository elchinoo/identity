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

Rate limits and sessions are per process. Access tokens cannot be revoked before they expire. One signing algorithm (RS256).
There is no MFA. Treat the identity provider as the most sensitive service in the fleet: restrict the admin console,
back up the database, and keep `IDENTITY_ENCRYPTION_KEY` out of the database host.
