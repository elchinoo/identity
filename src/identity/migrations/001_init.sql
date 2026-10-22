-- Identity: users, groups, applications (OAuth clients), role grants, codes, refresh tokens, signing keys, federation, audit.
-- The shared tables (app_setting, web_session, api_token, oidc_login) come from agentpg-kit.

CREATE TABLE idp_user (
    id            text PRIMARY KEY CHECK (id ~ '^usr_[a-z0-9]{12,24}$'),
    username      text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    email         text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    name          text NOT NULL DEFAULT '' CHECK (length(name) <= 120),
    password_hash text,                                   -- null: the person signs in only through a federated provider
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX idp_user_email_idx ON idp_user (lower(email));

CREATE TABLE idp_federated (          -- a person's account at an upstream provider
    provider    text NOT NULL,
    subject     text NOT NULL,
    user_id     text NOT NULL REFERENCES idp_user(id) ON DELETE CASCADE,
    email       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

CREATE TABLE idp_group (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    description text NOT NULL DEFAULT ''
);
CREATE TABLE idp_membership (
    user_id  text NOT NULL REFERENCES idp_user(id) ON DELETE CASCADE,
    group_id bigint NOT NULL REFERENCES idp_group(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE idp_app (                -- an application registered with the ecosystem (an OAuth client)
    client_id         text PRIMARY KEY CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{1,39}$'),
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    description       text NOT NULL DEFAULT '',
    kind              text NOT NULL CHECK (kind IN ('web', 'public', 'service')),   -- web: confidential, public: PKCE only, service: no users
    secret_hash       text,                                -- sha256 of the secret (it is long and random); null for public clients
    redirect_uris     text[] NOT NULL DEFAULT '{}',
    post_logout_uris  text[] NOT NULL DEFAULT '{}',
    allowed_scopes    text[] NOT NULL DEFAULT '{}',        -- scopes beyond openid/profile/email/roles/offline_access that it may request
    allowed_audiences text[] NOT NULL DEFAULT '{}',        -- other apps a service may obtain tokens for
    roles             jsonb NOT NULL DEFAULT '[]',         -- the roles this app defines: [{"name": "approver", "description": "..."}]
    default_roles     text[] NOT NULL DEFAULT '{}',        -- granted to every active user
    url               text NOT NULL DEFAULT '',            -- where the app lives (shown in the launcher)
    status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE idp_role_grant (         -- who holds which role in which app (directly or through a group)
    id           bigserial PRIMARY KEY,
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'group')),
    subject_id   text NOT NULL,
    client_id    text NOT NULL REFERENCES idp_app(client_id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role ~ '^[a-z0-9][a-z0-9._-]{0,39}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (subject_type, subject_id, client_id, role)
);

CREATE TABLE oauth_code (
    code_hash       text PRIMARY KEY,
    client_id       text NOT NULL REFERENCES idp_app(client_id) ON DELETE CASCADE,
    user_id         text NOT NULL REFERENCES idp_user(id) ON DELETE CASCADE,
    redirect_uri    text NOT NULL,
    scope           text NOT NULL DEFAULT '',
    nonce           text,
    code_challenge  text NOT NULL,
    challenge_method text NOT NULL DEFAULT 'S256',
    auth_time       bigint NOT NULL,
    expires_at      timestamptz NOT NULL
);

CREATE TABLE oauth_refresh (          -- refresh tokens rotate on every use; replaying an old one revokes the whole family
    id          bigserial PRIMARY KEY,
    token_hash  text NOT NULL UNIQUE,
    family_id   text NOT NULL,
    client_id   text NOT NULL REFERENCES idp_app(client_id) ON DELETE CASCADE,
    user_id     text NOT NULL REFERENCES idp_user(id) ON DELETE CASCADE,
    scope       text NOT NULL DEFAULT '',
    auth_time   bigint NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz
);
CREATE INDEX oauth_refresh_family_idx ON oauth_refresh (family_id);

CREATE TABLE signing_key (
    kid         text PRIMARY KEY,
    alg         text NOT NULL CHECK (alg IN ('RS256', 'ES256')),
    private_enc text NOT NULL,                              -- encrypted with the vault key
    public_jwk  jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retiring', 'retired')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    retire_at   timestamptz
);

CREATE TABLE federation_provider (
    provider        text PRIMARY KEY CHECK (provider IN ('google', 'github')),
    client_id       text NOT NULL,
    client_secret_enc text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    mode            text NOT NULL DEFAULT 'invite_only' CHECK (mode IN ('invite_only', 'open')),
    allowed_domains text[] NOT NULL DEFAULT '{}',          -- for open mode: only e-mail addresses in these domains may sign up
    default_groups  text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE idp_audit (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,
    action  text NOT NULL,
    target  text NOT NULL DEFAULT '',
    detail  jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX idp_audit_at_idx ON idp_audit (at DESC);
