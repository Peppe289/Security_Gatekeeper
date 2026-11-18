-- Routes: path prefix -> upstream. Source of truth for every gateway instance.
CREATE TABLE routes (
    prefix            VARCHAR(63)   PRIMARY KEY,
    target_url        VARCHAR(2048) NOT NULL,
    enabled           BOOLEAN       NOT NULL DEFAULT TRUE,
    api_key_hash      CHAR(64),
    burst_capacity    BIGINT        NOT NULL CHECK (burst_capacity BETWEEN 1 AND 1000000),
    refill_per_second BIGINT        NOT NULL CHECK (refill_per_second BETWEEN 1 AND 1000000000),
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- Audit log: one SHA-256 hash chain per gateway node (node_id), so several
-- instances can write concurrently without coordinating sequence numbers.
CREATE TABLE audit_log (
    node_id       VARCHAR(64)  NOT NULL,
    sequence      BIGINT       NOT NULL CHECK (sequence >= 0),
    ts            TIMESTAMPTZ  NOT NULL,
    client_ip     VARCHAR(45)  NOT NULL,
    method        VARCHAR(16)  NOT NULL,
    path          VARCHAR(515) NOT NULL,
    route_prefix  VARCHAR(63)  NOT NULL,
    decision      VARCHAR(32)  NOT NULL,
    http_status   INTEGER      NOT NULL,
    previous_hash CHAR(64)     NOT NULL,
    hash          CHAR(64)     NOT NULL,
    PRIMARY KEY (node_id, sequence)
);

CREATE INDEX audit_log_ts_idx ON audit_log (ts DESC);

-- Defence in depth: rows can be appended (and old ones purged) but never modified.
-- Tampering by someone able to bypass this is still detected by chain verification.
CREATE FUNCTION audit_log_reject_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_update();
