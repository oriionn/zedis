-- The bridge's stores in PostgreSQL (ADR 18). Every statement runs again
-- safely: a migration that stopped halfway is finished by running it again.
--
-- Records are documents (`doc`, the record's JSON) beside the columns a
-- statement needs; times are unix milliseconds unless named `_secs`.

-- The count of changes to each set a process keeps in memory.
CREATE TABLE IF NOT EXISTS store_versions (
    name TEXT PRIMARY KEY,
    version BIGINT NOT NULL
);
INSERT INTO store_versions (name, version)
VALUES ('servers', 0), ('accounts', 0), ('logins_revoked', 0)
ON CONFLICT (name) DO NOTHING;

-- What the store says about itself: the master key's check value.
CREATE TABLE IF NOT EXISTS store_meta (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    name TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    expires_at_secs BIGINT NOT NULL,
    doc TEXT NOT NULL
);

-- Secrets in `doc` are sealed with the master key.
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    owner TEXT NULL,
    version BIGINT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logins (
    login_key TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    last_used_secs BIGINT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS throttle (
    id BIGSERIAL PRIMARY KEY,
    process_id TEXT NOT NULL,
    key_sha256 TEXT NOT NULL,
    attempt_key TEXT NOT NULL,
    at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS throttle_key ON throttle (key_sha256);
CREATE INDEX IF NOT EXISTS throttle_at ON throttle (at_ms);

-- One row at most: the waiting token's hash.
CREATE TABLE IF NOT EXISTS setup_token (
    id INTEGER PRIMARY KEY,
    token_sha256 TEXT NOT NULL,
    created_at_secs BIGINT NOT NULL
);

-- A row per server whose bin is in use: what a put locks, so two
-- processes making room in one bin do it one after the other.
CREATE TABLE IF NOT EXISTS trash_bins (
    server_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS trash (
    server_id TEXT NOT NULL,
    id TEXT NOT NULL,
    deleted_at BIGINT NOT NULL,
    size_bytes BIGINT NOT NULL,
    meta TEXT NOT NULL,
    PRIMARY KEY (server_id, id)
);
CREATE INDEX IF NOT EXISTS trash_deleted_at ON trash (deleted_at);
-- The payloads apart, so a listing never reads one (ADR 17's blobs).
CREATE TABLE IF NOT EXISTS trash_payloads (
    server_id TEXT NOT NULL,
    id TEXT NOT NULL,
    payload BYTEA NOT NULL,
    PRIMARY KEY (server_id, id)
);

-- One sample a minute per server: the key says so.
CREATE TABLE IF NOT EXISTS metrics (
    server_id TEXT NOT NULL,
    minute BIGINT NOT NULL,
    ts_ms BIGINT NOT NULL,
    sample TEXT NOT NULL,
    PRIMARY KEY (server_id, minute)
);
CREATE INDEX IF NOT EXISTS metrics_ts ON metrics (ts_ms);

CREATE TABLE IF NOT EXISTS page_rows (
    account TEXT NOT NULL,
    row_table TEXT NOT NULL,
    row_key TEXT NOT NULL,
    row_value TEXT NOT NULL,
    PRIMARY KEY (account, row_table, row_key)
);

-- Keyed by the Redis key's SHA-256: a key name can be longer than an
-- index entry may be.
CREATE TABLE IF NOT EXISTS key_notes (
    server_id TEXT NOT NULL,
    key_sha256 TEXT NOT NULL,
    redis_key TEXT NOT NULL,
    doc TEXT NOT NULL,
    PRIMARY KEY (server_id, key_sha256)
);

CREATE TABLE IF NOT EXISTS scripts (
    id TEXT PRIMARY KEY,
    owner TEXT NULL,
    doc TEXT NOT NULL
);
