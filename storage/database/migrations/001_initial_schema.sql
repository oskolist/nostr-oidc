-- +goose Up

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    secret TEXT,
    redirect_uris TEXT,
    application_type INTEGER,
    auth_method TEXT,
    response_types TEXT,
    grant_types TEXT,
    access_token_type INTEGER,
    dev_mode BOOLEAN,
    id_token_userinfo_claims_assertion BOOLEAN,
    clock_skew INTEGER,
    post_logout_redirect_uri_globs TEXT,
    redirect_uri_globs TEXT
);

CREATE TABLE auth_requests (
    id TEXT PRIMARY KEY,
    creation_date DATETIME,
    application_id TEXT,
    callback_uri TEXT,
    transfer_state TEXT,
    prompt TEXT,
    ui_locales TEXT,
    login_hint TEXT,
    max_auth_age INTEGER,
    user_id TEXT,
    scopes TEXT,
    response_type TEXT,
    response_mode TEXT,
    nonce TEXT,
    code_challenge_challenge TEXT,
    code_challenge_method TEXT
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    npub BLOB UNIQUE,
    preferred_language TEXT,
    is_admin BOOLEAN
);

CREATE TABLE tokens (
    id TEXT PRIMARY KEY,
    application_id TEXT,
    subject TEXT,
    refresh_token_id TEXT,
    audience TEXT,
    expiration DATETIME,
    scopes TEXT
);

CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY,
    token TEXT,
    auth_time DATETIME,
    amr TEXT,
    audience TEXT,
    user_id TEXT,
    application_id TEXT,
    expiration DATETIME,
    scopes TEXT,
    access_token TEXT
);

CREATE TABLE device_authorizations (
    device_code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL
);

-- Indexes
CREATE UNIQUE INDEX idx_clients_id ON clients(id);
CREATE UNIQUE INDEX idx_auth_requests_id ON auth_requests(id);
CREATE INDEX idx_auth_requests_user_id ON auth_requests(user_id);
CREATE INDEX idx_auth_requests_application_id ON auth_requests(application_id);
CREATE UNIQUE INDEX idx_users_id ON users(id);
CREATE UNIQUE INDEX idx_tokens_id ON tokens(id);
CREATE UNIQUE INDEX idx_refresh_tokens_id ON refresh_tokens(id);
CREATE UNIQUE INDEX idx_users_npub ON users(npub);
CREATE UNIQUE INDEX idx_device_authorizations_device_code ON device_authorizations(device_code);
CREATE UNIQUE INDEX idx_device_authorizations_user_code ON device_authorizations(user_code);

-- +goose Down

DROP TABLE IF EXISTS device_authorizations;
DROP TABLE IF EXISTS auth_requests;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS clients;

DROP INDEX IF EXISTS idx_device_authorizations_user_code;
DROP INDEX IF EXISTS idx_device_authorizations_device_code;
DROP INDEX IF EXISTS idx_refresh_tokens_id;
DROP INDEX IF EXISTS idx_tokens_id;
DROP INDEX IF EXISTS idx_auth_requests_id;
DROP INDEX IF EXISTS idx_auth_requests_user_id;
DROP INDEX IF EXISTS idx_auth_requests_application_id;
DROP INDEX IF EXISTS idx_users_id;
DROP INDEX IF EXISTS idx_clients_id;
DROP INDEX IF EXISTS idx_users_npub;
