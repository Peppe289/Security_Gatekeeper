package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChainVerifier;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.support.IntegrationTest;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Database round trip of the hash chain: what is written must verify, and a
 * change made by someone bypassing the append-only trigger must be detected.
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
    JdbcTemplate jdbc;

    @AfterEach
    void cleanUp() {
        jdbc.update("DELETE FROM audit_log WHERE node_id = ?", NODE);
    }

    private void writeChain(int n) {
        AuditChain chain = new AuditChain();
        List<AuditRecord> records = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            records.add(chain.append(1_700_000_000_123L + i, "10.0.0.1", "GET", "/r/" + i, "r", "ALLOW", 200));
        }
        repository.insertBatch(NODE, records);
    }

    @Test
    void persistedChainVerifies() {
        writeChain(5);
        AuditChainVerifier v = audit.verifyNode(NODE);
        assertTrue(v.isValid());
        assertEquals(5, v.checkedCount());
        assertEquals(4, repository.findHead(NODE).orElseThrow().lastSequence());
    }

    @Test
    void updatesAreRejectedByTheDatabase() {
        writeChain(1);
        assertThrows(DataAccessException.class,
                () -> jdbc.update("UPDATE audit_log SET http_status = 500 WHERE node_id = ?", NODE));
    }

    @Test
    void tamperingThatBypassesTheTriggerIsDetected() {
        writeChain(5);
        jdbc.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update");
        try {
            jdbc.update("UPDATE audit_log SET http_status = 500, decision = 'FORWARD_FAILED' "
                    + "WHERE node_id = ? AND sequence = 2", NODE);
        } finally {
            jdbc.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update");
        }
        AuditChainVerifier v = audit.verifyNode(NODE);
        assertFalse(v.isValid());
        assertEquals(2, v.firstInvalidSequence());
        assertEquals(2, v.checkedCount());
    }

    @Test
    void deletedRecordInTheMiddleIsDetected() {
        writeChain(5);
        jdbc.update("DELETE FROM audit_log WHERE node_id = ? AND sequence = 3", NODE);
        AuditChainVerifier v = audit.verifyNode(NODE);
        assertFalse(v.isValid());
        assertEquals(4, v.firstInvalidSequence());
    }
}
