-- The bridge's stores in MySQL 8.0.19 and later (ADR 18). Every statement
-- runs again safely: MySQL does not run DDL in a transaction, and a
-- migration that stopped halfway is finished by running it again.
--
-- Every table is utf8mb4 with the binary collation: MySQL's default
-- (utf8mb4_0900_ai_ci) ignores case and accents, which would make `Alice`
-- and `alice` one account. Records are documents (`doc`, the record's
-- JSON) beside the columns a statement needs; times are unix milliseconds
-- unless named `_secs`. Column sizes follow what the bridge accepts: an
-- account name is at most 64 characters, an id 128, a row key 512.

CREATE TABLE IF NOT EXISTS store_versions (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    version BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
INSERT IGNORE INTO store_versions (name, version)
VALUES ('servers', 0), ('accounts', 0), ('logins_revoked', 0);

CREATE TABLE IF NOT EXISTS store_meta (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS accounts (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS invites (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    expires_at_secs BIGINT NOT NULL,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS servers (
    id VARCHAR(191) NOT NULL PRIMARY KEY,
    owner VARCHAR(64) NULL,
    version BIGINT NOT NULL,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS logins (
    login_key VARCHAR(128) NOT NULL PRIMARY KEY,
    account VARCHAR(64) NOT NULL,
    last_used_secs BIGINT NOT NULL,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS throttle (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    process_id VARCHAR(64) NOT NULL,
    key_sha256 VARCHAR(64) NOT NULL,
    attempt_key MEDIUMTEXT NOT NULL,
    at_ms BIGINT NOT NULL,
    INDEX throttle_key (key_sha256),
    INDEX throttle_at (at_ms)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS setup_token (
    id INT NOT NULL PRIMARY KEY,
    token_sha256 VARCHAR(64) NOT NULL,
    created_at_secs BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS trash_bins (
    server_id VARCHAR(191) NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS trash (
    server_id VARCHAR(191) NOT NULL,
    id VARCHAR(64) NOT NULL,
    deleted_at BIGINT NOT NULL,
    size_bytes BIGINT NOT NULL,
    meta MEDIUMTEXT NOT NULL,
    PRIMARY KEY (server_id, id),
    INDEX trash_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- A payload is up to 1 MB and its seal; BLOB stops at 64 KB.
CREATE TABLE IF NOT EXISTS trash_payloads (
    server_id VARCHAR(191) NOT NULL,
    id VARCHAR(64) NOT NULL,
    payload LONGBLOB NOT NULL,
    PRIMARY KEY (server_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS metrics (
    server_id VARCHAR(191) NOT NULL,
    minute BIGINT NOT NULL,
    ts_ms BIGINT NOT NULL,
    sample MEDIUMTEXT NOT NULL,
    PRIMARY KEY (server_id, minute),
    INDEX metrics_ts (ts_ms)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS page_rows (
    account VARCHAR(64) NOT NULL,
    row_table VARCHAR(32) NOT NULL,
    row_key VARCHAR(512) NOT NULL,
    row_value MEDIUMTEXT NOT NULL,
    PRIMARY KEY (account, row_table, row_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS key_notes (
    server_id VARCHAR(191) NOT NULL,
    key_sha256 VARCHAR(64) NOT NULL,
    redis_key MEDIUMTEXT NOT NULL,
    doc MEDIUMTEXT NOT NULL,
    PRIMARY KEY (server_id, key_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS scripts (
    id VARCHAR(191) NOT NULL PRIMARY KEY,
    owner VARCHAR(64) NULL,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
