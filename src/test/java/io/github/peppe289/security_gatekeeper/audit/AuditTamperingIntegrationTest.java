package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.SignedRecord;
import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.support.IntegrationTest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Database round trip of the authenticated hash chain: what is written must
 * verify, and changes made by someone who can write to the database (even
 * bypassing the append-only trigger and recomputing hashes) must be detected.
 * Uses its own node id and cleans up, so the shared chain stays valid.
 */
@IntegrationTest
class AuditTamperingIntegrationTest {

    private static final String NODE = "tamper-node";

    @Autowired
    AuditRepository repository;

    @Autowired
    AuditService audit;

    @Autowired
    AuditKeys keys;

    @Autowired
    AuditAnchorStore anchors;

    @Autowired
    GatewayProperties properties;

    @Autowired
    JdbcTemplate jdbc;

    @AfterEach
    void cleanUp() throws Exception {
        jdbc.update("DELETE FROM audit_log WHERE node_id = ?", NODE);
        Files.deleteIfExists(Path.of(properties.audit().anchorDir(), NODE + ".anchors"));
    }

    private List<AuditRecord> writeChain(int n) {
        AuditChain chain = new AuditChain();
        List<AuditRecord> records = new ArrayList<>();
        List<SignedRecord> signed = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            AuditRecord rec = chain.append(1_700_000_000_123L + i, "10.0.0.1", "GET", "/r/" + i, "r", "ALLOW", 200);
            AuditKeys.Signature s = keys.sign(AuditKeys.recordMessage(NODE, rec));
            records.add(rec);
            signed.add(new SignedRecord(rec, s.keyId(), s.mac()));
        }
        repository.insertBatch(NODE, signed);
        return records;
    }

    private void anchor(AuditRecord rec) throws Exception {
        anchors.append(AuditAnchor.create(NODE, rec.getSequence(), rec.getHash(), 1_700_000_100_000L, keys));
    }

    /** Runs {@code sql} with the append-only trigger disabled, as an attacker with full database access could. */
    private void bypassingTrigger(String sql, Object... args) {
        jdbc.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update");
        try {
            jdbc.update(sql, args);
        } finally {
            jdbc.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update");
        }
    }

    @Test
    void persistedChainVerifies() throws Exception {
        List<AuditRecord> records = writeChain(5);
        anchor(records.get(4));
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertTrue(r.valid(), r.problem());
        assertEquals(5, r.checkedRecords());
        assertEquals(1, r.anchors());
        assertEquals(4, repository.findHead(NODE).orElseThrow().lastSequence());
    }

    @Test
    void updatesAreRejectedByTheDatabase() {
        writeChain(1);
        assertThrows(DataAccessException.class,
                () -> jdbc.update("UPDATE audit_log SET http_status = 500 WHERE node_id = ?", NODE));
    }

    @Test
    void tamperingThatBypassesTheTriggerIsDetected() throws Exception {
        writeChain(5);
        bypassingTrigger("UPDATE audit_log SET http_status = 500, decision = 'FORWARD_FAILED' "
                + "WHERE node_id = ? AND sequence = 2", NODE);
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertFalse(r.valid());
        assertEquals(2, r.firstInvalidSequence());
        assertEquals(2, r.checkedRecords());
    }

    @Test
    void chainRewrittenWithoutTheKeyIsDetected() throws Exception {
        List<AuditRecord> records = writeChain(5);
        // The attacker changes record #2 and recomputes the hashes of #2..#4, which needs no secret,
        // but cannot produce the matching MACs.
        AuditChain forged = new AuditChain(2, records.get(1).getHash());
        for (int i = 2; i < 5; i++) {
            AuditRecord original = records.get(i);
            AuditRecord rec = forged.append(original.getTimestampMillis(), original.getClientIp(), "DELETE",
                    original.getPath(), original.getRoutePrefix(), original.getDecision(), original.getHttpStatus());
            bypassingTrigger("UPDATE audit_log SET method = ?, previous_hash = ?, hash = ? "
                    + "WHERE node_id = ? AND sequence = ?", rec.getMethod(), rec.getPreviousHash(), rec.getHash(),
                    NODE, rec.getSequence());
        }
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertFalse(r.valid());
        assertEquals(2, r.firstInvalidSequence());
        assertTrue(r.problem().contains("MAC"), r.problem());
    }

    @Test
    void strippedMacIsDetected() throws Exception {
        writeChain(3);
        bypassingTrigger("UPDATE audit_log SET mac = NULL, mac_key_id = NULL WHERE node_id = ? AND sequence = 1", NODE);
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertFalse(r.valid());
        assertEquals(1, r.firstInvalidSequence());
        assertEquals("record has no MAC", r.problem());
    }

    @Test
    void deletedRecordInTheMiddleIsDetected() throws Exception {
        writeChain(5);
        jdbc.update("DELETE FROM audit_log WHERE node_id = ? AND sequence = 3", NODE);
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertFalse(r.valid());
        assertEquals(4, r.firstInvalidSequence());
    }

    @Test
    void recordsDeletedFromTheEndAreDetectedThroughAnchors() throws Exception {
        List<AuditRecord> records = writeChain(5);
        anchor(records.get(4));
        jdbc.update("DELETE FROM audit_log WHERE node_id = ? AND sequence >= 3", NODE);
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertFalse(r.valid());
        assertEquals(3, r.firstInvalidSequence());
        assertTrue(r.problem().contains("missing at the end"), r.problem());
    }

    @Test
    void deletedChainIsDetectedThroughAnchors() throws Exception {
        List<AuditRecord> records = writeChain(3);
        anchor(records.get(2));
        jdbc.update("DELETE FROM audit_log WHERE node_id = ?", NODE);
        AuditService.IntegrityReport report = audit.verifyAll();
        assertFalse(report.valid());
        assertEquals(NODE, report.brokenNode());
        assertTrue(report.problem().contains("chain is missing"), report.problem());
    }

    @Test
    void retentionOfTheOldestRecordsIsAccepted() throws Exception {
        List<AuditRecord> records = writeChain(5);
        anchor(records.get(1));
        anchor(records.get(4));
        jdbc.update("DELETE FROM audit_log WHERE node_id = ? AND sequence < 2", NODE);
        NodeVerifier.Result r = audit.verifyNode(NODE);
        assertTrue(r.valid(), r.problem());
        assertEquals(3, r.checkedRecords());
    }
}
