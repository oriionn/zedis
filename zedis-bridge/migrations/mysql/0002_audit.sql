-- The audit in the database (ADR 18): every bridge's lines in one table,
-- looked up by time, account, event and server. `line` is the JSON object
-- the file would have held. An account is at most 64 characters; a name
-- someone tried, which the audit also files, is cut to the same.
CREATE TABLE IF NOT EXISTS audit (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    at_ms BIGINT NOT NULL,
    account VARCHAR(255) NOT NULL,
    event VARCHAR(64) NOT NULL,
    server_id VARCHAR(191) NULL,
    line MEDIUMTEXT NOT NULL,
    INDEX audit_at (at_ms),
    INDEX audit_account (account, id),
    INDEX audit_event (event, id),
    INDEX audit_server (server_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
