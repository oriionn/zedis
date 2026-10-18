-- Requests for an account, waiting for an administrator (ADR 17, amended
-- 2026-10-18): records beside the accounts and the invitations, changed
-- under the same `accounts` counter.
CREATE TABLE IF NOT EXISTS signups (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    expires_at_secs BIGINT NOT NULL,
    doc MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
