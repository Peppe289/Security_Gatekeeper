package io.github.peppe289.security_gatekeeper.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import org.junit.jupiter.api.Test;

class AuditRecordTest {

    private static final String PREV = AuditChain.GENESIS_HASH;

    private static AuditRecord sample() {
        return AuditRecord.create(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 200, PREV);
    }

    @Test
    void createStoresFieldsAndComputesHash() {
        AuditRecord r = sample();
        assertEquals(3, r.getSequence());
        assertEquals(1_700_000_000_000L, r.getTimestampMillis());
        assertEquals("10.0.0.1", r.getClientIp());
        assertEquals("GET", r.getMethod());
        assertEquals("/a/x", r.getPath());
        assertEquals("a", r.getRoutePrefix());
        assertEquals("ALLOW", r.getDecision());
        assertEquals(200, r.getHttpStatus());
        assertEquals(PREV, r.getPreviousHash());
        assertTrue(Sha256.isHexDigest(r.getHash()));
        assertEquals(AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 200, PREV),
                r.getHash());
        assertTrue(r.isHashValid());
    }

    @Test
    void hashIsStableKnownValue() {
        String canonical = "1:3|13:1700000000000|8:10.0.0.1|3:GET|4:/a/x|1:a|5:ALLOW|3:200|64:" + PREV + "|";
        assertEquals(Sha256.hex(canonical), sample().getHash());
    }

    @Test
    void everyFieldContributesToHash() {
        AuditRecord r = sample();
        String h = r.getHash();
        assertNotEquals(h, AuditRecord.computeHash(4, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_001L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.2", "GET", "/a/x", "a", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "PUT", "/a/x", "a", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/y", "a", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "b", "ALLOW", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "DENY", 200, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 201, PREV));
        assertNotEquals(h, AuditRecord.computeHash(3, 1_700_000_000_000L, "10.0.0.1", "GET", "/a/x", "a", "ALLOW", 200, Sha256.hex("x")));
    }

    @Test
    void canonicalFormIsUnambiguous() {
        String a = AuditRecord.computeHash(0, 0, "ip", "GET", "a|b", "c", "ALLOW", 200, PREV);
        String b = AuditRecord.computeHash(0, 0, "ip", "GET", "a", "b|c", "ALLOW", 200, PREV);
        assertNotEquals(a, b);
    }

    @Test
    void tamperedRecordIsDetected() {
        AuditRecord r = sample();
        AuditRecord forged = new AuditRecord(r.getSequence(), r.getTimestampMillis(), r.getClientIp(), r.getMethod(),
                r.getPath(), r.getRoutePrefix(), "ALLOW", 500, r.getPreviousHash(), r.getHash());
        assertFalse(forged.isHashValid());
    }

    @Test
    void constructorValidatesArguments() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new AuditRecord(-1, 0, "ip", "GET", "/", "", "ALLOW", 200, PREV, PREV));
        assertEquals("sequence must be >= 0", e.getMessage());
        new AuditRecord(0, 0, "ip", "GET", "/", "", "ALLOW", 200, PREV, PREV);
        String[][] nulls = {
                {null, "GET", "/", "", "ALLOW", PREV, PREV},
                {"ip", null, "/", "", "ALLOW", PREV, PREV},
                {"ip", "GET", null, "", "ALLOW", PREV, PREV},
                {"ip", "GET", "/", null, "ALLOW", PREV, PREV},
                {"ip", "GET", "/", "", null, PREV, PREV},
                {"ip", "GET", "/", "", "ALLOW", null, PREV},
                {"ip", "GET", "/", "", "ALLOW", PREV, null},
        };
        for (String[] f : nulls) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> new AuditRecord(0, 0, f[0], f[1], f[2], f[3], f[4], 200, f[5], f[6]));
            assertEquals("audit fields must not be null", ex.getMessage());
        }
    }
}
