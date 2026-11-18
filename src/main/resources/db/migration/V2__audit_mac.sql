-- Authenticated audit trail: every record is signed with HMAC-SHA256(key, node_id | hash).
-- The key lives only in the gateway configuration, so whoever can write to this table can
-- no longer rewrite a record and recompute the chain without verification noticing
-- (the hash chain alone uses no secret, contrary to what the comment in V1 suggests).
--
-- mac_key_id is the fingerprint of the signing key, to support key rotation.
-- Rows written before this migration have no MAC and fail verification.
ALTER TABLE audit_log
    ADD COLUMN mac_key_id CHAR(16),
    ADD COLUMN mac        CHAR(64),
    ADD CONSTRAINT audit_log_mac_complete CHECK ((mac_key_id IS NULL) = (mac IS NULL));
