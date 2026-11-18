package io.github.peppe289.security_gatekeeper.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuditChainTest {

    private static AuditRecord add(AuditChain c, int i) {
        return c.append(1000L + i, "10.0.0." + i, "GET", "/a/" + i, "a", "ALLOW", 200);
    }

    private static List<AuditRecord> chainOf(int n) {
        AuditChain c = new AuditChain();
        List<AuditRecord> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            list.add(add(c, i));
        }
        return list;
    }

    private static final int VALID = -1;

    /** Index of the first record the verifier rejects, or {@link #VALID}. */
    private static int verify(List<AuditRecord> records, String anchorHash) {
        AuditChainVerifier verifier = new AuditChainVerifier(anchorHash);
        for (int i = 0; i < records.size(); i++) {
            if (!verifier.accept(records.get(i))) {
                return i;
            }
        }
        return VALID;
    }

    private static AuditRecord copyWith(AuditRecord r, long seq, int status, String prev, String hash) {
        return new AuditRecord(seq, r.getTimestampMillis(), r.getClientIp(), r.getMethod(), r.getPath(),
                r.getRoutePrefix(), r.getDecision(), status, prev, hash);
    }

    @Test
    void newChainStartsAtGenesis() {
        AuditChain c = new AuditChain();
        assertEquals(0, c.nextSequence());
        assertEquals(AuditChain.GENESIS_HASH, c.headHash());
        assertTrue(Sha256.isHexDigest(AuditChain.GENESIS_HASH));
    }

    @Test
    void appendLinksRecordsAndAdvancesHead() {
        AuditChain c = new AuditChain();
        AuditRecord r0 = add(c, 0);
        AuditRecord r1 = add(c, 1);
        assertEquals(0, r0.getSequence());
        assertEquals(1, r1.getSequence());
        assertEquals(AuditChain.GENESIS_HASH, r0.getPreviousHash());
        assertEquals(r0.getHash(), r1.getPreviousHash());
        assertEquals(r1.getHash(), c.headHash());
        assertEquals(2, c.nextSequence());
        assertEquals(1000L, r0.getTimestampMillis());
        assertEquals("10.0.0.1", r1.getClientIp());
        assertEquals("/a/1", r1.getPath());
        assertEquals(200, r1.getHttpStatus());
    }

    @Test
    void resumedChainContinuesSeamlessly() {
        List<AuditRecord> first = chainOf(3);
        AuditRecord last = first.get(2);
        AuditChain resumed = new AuditChain(last.getSequence() + 1, last.getHash());
        assertEquals(3, resumed.nextSequence());
        AuditRecord next = add(resumed, 3);
        List<AuditRecord> all = new ArrayList<>(first);
        all.add(next);
        assertEquals(VALID, verify(all, AuditChain.GENESIS_HASH));
        // same content as an uninterrupted chain
        assertEquals(chainOf(4).get(3).getHash(), next.getHash());
    }

    @Test
    void resumeValidatesArguments() {
        assertEquals("nextSequence must be >= 0", assertThrows(IllegalArgumentException.class,
                () -> new AuditChain(-1, AuditChain.GENESIS_HASH)).getMessage());
        assertEquals("headHash must be a SHA-256 hex digest", assertThrows(IllegalArgumentException.class,
                () -> new AuditChain(0, "nope")).getMessage());
        assertEquals(0, new AuditChain(0, AuditChain.GENESIS_HASH).nextSequence());
    }

    @Test
    void verifyEmptyListIsValid() {
        assertEquals(VALID, verify(List.of(), AuditChain.GENESIS_HASH));
    }

    @Test
    void verifyIntactChain() {
        assertEquals(VALID, verify(chainOf(5), AuditChain.GENESIS_HASH));
    }

    @Test
    void detectsModifiedContent() {
        List<AuditRecord> recs = chainOf(4);
        AuditRecord r = recs.get(2);
        recs.set(2, copyWith(r, r.getSequence(), 500, r.getPreviousHash(), r.getHash()));
        assertEquals(2, verify(recs, AuditChain.GENESIS_HASH));
    }

    @Test
    void detectsRecomputedHashThatBreaksTheLink() {
        List<AuditRecord> recs = chainOf(4);
        AuditRecord r = recs.get(1);
        recs.set(1, AuditRecord.create(r.getSequence(), r.getTimestampMillis(), r.getClientIp(), r.getMethod(),
                r.getPath(), r.getRoutePrefix(), "ALLOW", 500, r.getPreviousHash()));
        // the forged record is self-consistent, but its successor no longer links to it
        assertEquals(2, verify(recs, AuditChain.GENESIS_HASH));
    }

    @Test
    void detectsRemovedAndSwappedRecords() {
        List<AuditRecord> removed = chainOf(4);
        removed.remove(1);
        assertEquals(1, verify(removed, AuditChain.GENESIS_HASH));

        List<AuditRecord> swapped = chainOf(4);
        AuditRecord tmp = swapped.get(1);
        swapped.set(1, swapped.get(2));
        swapped.set(2, tmp);
        assertEquals(1, verify(swapped, AuditChain.GENESIS_HASH));
    }

    @Test
    void detectsWrongAnchor() {
        List<AuditRecord> recs = chainOf(3);
        assertEquals(0, verify(recs, recs.get(0).getHash()));
    }

    @Test
    void detectsSequenceGapEvenWithValidHashes() {
        List<AuditRecord> recs = chainOf(2);
        AuditRecord r1 = recs.get(1);
        recs.set(1, AuditRecord.create(5, r1.getTimestampMillis(), r1.getClientIp(), r1.getMethod(),
                r1.getPath(), r1.getRoutePrefix(), r1.getDecision(), r1.getHttpStatus(), r1.getPreviousHash()));
        assertEquals(1, verify(recs, AuditChain.GENESIS_HASH));
    }

    @Test
    void windowStartingMidChainVerifiesAgainstItsAnchor() {
        List<AuditRecord> recs = chainOf(5);
        assertEquals(VALID, verify(recs.subList(2, 5), recs.get(1).getHash()));
    }

    // --- incremental verifier ----------------------------------------------------------

    @Test
    void verifierCountsAndStaysInvalidAfterFirstFailure() {
        List<AuditRecord> recs = chainOf(4);
        AuditRecord r = recs.get(1);
        recs.set(1, copyWith(r, r.getSequence(), 418, r.getPreviousHash(), r.getHash()));

        AuditChainVerifier v = new AuditChainVerifier(AuditChain.GENESIS_HASH);
        assertTrue(v.isValid());
        assertEquals(-1, v.firstInvalidSequence());
        assertTrue(v.accept(recs.get(0)));
        assertEquals(1, v.checkedCount());
        assertFalse(v.accept(recs.get(1)));
        assertFalse(v.isValid());
        assertEquals(1, v.firstInvalidSequence());
        assertFalse(v.accept(recs.get(2)), "stays invalid");
        assertEquals(1, v.checkedCount());
        assertEquals(1, v.firstInvalidSequence());
    }

    @Test
    void verifierAcceptsWindowNotStartingAtZero() {
        List<AuditRecord> recs = chainOf(5);
        AuditChainVerifier v = new AuditChainVerifier(recs.get(2).getPreviousHash());
        for (AuditRecord r : recs.subList(2, 5)) {
            assertTrue(v.accept(r));
        }
        assertEquals(3, v.checkedCount());
        assertTrue(v.isValid());
    }

    @Test
    void verifierRejectsNullAnchor() {
        assertThrows(IllegalArgumentException.class, () -> new AuditChainVerifier(null));
    }
}
