-- The audit in the database (ADR 18): every bridge's lines in one table,
-- looked up by time, account, event and server. `line` is the JSON object
-- the file would have held.
CREATE TABLE IF NOT EXISTS audit (
    id BIGSERIAL PRIMARY KEY,
    at_ms BIGINT NOT NULL,
    account TEXT NOT NULL,
    event TEXT NOT NULL,
    server_id TEXT NULL,
    line TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_at ON audit (at_ms);
CREATE INDEX IF NOT EXISTS audit_account ON audit (account, id);
CREATE INDEX IF NOT EXISTS audit_event ON audit (event, id);
CREATE INDEX IF NOT EXISTS audit_server ON audit (server_id, id);
