package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.SignedRecord;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class NodeVerifierTest {

    private static final String NODE = "node-a";

    private final AuditKeys keys = new AuditKeys(AuditKeysTest.KEY, List.of());

    private List<SignedRecord> chain(int n) {
        AuditChain chain = new AuditChain();
        List<SignedRecord> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(sign(chain.append(1_700_000_000_000L + i, "10.0.0.1", "GET", "/r/" + i, "r", "ALLOW", 200)));
        }
        return out;
    }

    private SignedRecord sign(AuditRecord rec) {
        AuditKeys.Signature s = keys.sign(AuditKeys.recordMessage(NODE, rec));
        return new SignedRecord(rec, s.keyId(), s.mac());
    }

    private AuditAnchor anchorOf(SignedRecord s) {
        return AuditAnchor.create(NODE, s.record().getSequence(), s.record().getHash(), 1L, keys);
    }

    private NodeVerifier.Result verify(List<SignedRecord> records, List<AuditAnchor> anchors) {
        NodeVerifier v = new NodeVerifier(NODE, keys, anchors);
        for (SignedRecord r : records) {
            if (!v.accept(r)) {
                break;
            }
        }
        return v.finish();
    }

    @Test
    void signedAndAnchoredChainIsValid() {
        List<SignedRecord> records = chain(4);
        NodeVerifier.Result r = verify(records, List.of(anchorOf(records.get(1)), anchorOf(records.get(3))));
        assertTrue(r.valid(), r.problem());
        assertEquals(4, r.checkedRecords());
        assertEquals(2, r.anchors());
        assertEquals(-1, r.firstInvalidSequence());
    }

    @Test
    void emptyChainWithoutAnchorsIsValid() {
        assertTrue(verify(List.of(), List.of()).valid());
    }

    @Test
    void recordSignedForAnotherNodeIsRejected() {
        List<SignedRecord> records = chain(2);
        AuditRecord rec = records.get(1).record();
        AuditKeys.Signature other = keys.sign(AuditKeys.recordMessage("node-b", rec));
        records.set(1, new SignedRecord(rec, other.keyId(), other.mac()));
        NodeVerifier.Result r = verify(records, List.of());
        assertFalse(r.valid());
        assertEquals(1, r.firstInvalidSequence());
    }

    @Test
    void recordWithoutMacIsRejected() {
        List<SignedRecord> records = chain(2);
        records.set(0, new SignedRecord(records.get(0).record(), null, null));
        NodeVerifier.Result r = verify(records, List.of());
        assertFalse(r.valid());
        assertEquals(0, r.firstInvalidSequence());
        assertEquals("record has no MAC", r.problem());
    }

    @Test
    void recordDifferentFromItsAnchorIsRejected() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(1));
        AuditAnchor wrong = AuditAnchor.create(NODE, 1, "b".repeat(64), a.timestampMillis(), keys);
        NodeVerifier.Result r = verify(records, List.of(wrong));
        assertFalse(r.valid());
        assertEquals(1, r.firstInvalidSequence());
    }

    @Test
    void forgedAnchorIsRejected() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(2));
        AuditAnchor forged = new AuditAnchor(NODE, 9, a.hash(), a.timestampMillis(), a.keyId(), a.mac());
        NodeVerifier.Result r = verify(records, List.of(forged));
        assertFalse(r.valid());
        assertEquals(9, r.firstInvalidSequence());
        assertEquals("anchor #9 is not authentic", r.problem());
    }

    @Test
    void conflictingAnchorsAreRejected() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(1));
        AuditAnchor b = AuditAnchor.create(NODE, 1, "c".repeat(64), 2L, keys);
        assertFalse(verify(records, List.of(a, b)).valid());
    }

    @Test
    void truncatedChainIsRejected() {
        List<SignedRecord> records = chain(5);
        AuditAnchor last = anchorOf(records.get(4));
        NodeVerifier.Result r = verify(records.subList(0, 3), List.of(last));
        assertFalse(r.valid());
        assertEquals(3, r.firstInvalidSequence());
    }

    @Test
    void missingChainIsRejected() {
        List<SignedRecord> records = chain(2);
        NodeVerifier.Result r = verify(List.of(), List.of(anchorOf(records.get(1))));
        assertFalse(r.valid());
        assertEquals(1, r.firstInvalidSequence());
    }

    @Test
    void anchorsOlderThanTheRetainedRecordsAreIgnored() {
        List<SignedRecord> records = chain(5);
        NodeVerifier.Result r = verify(records.subList(2, 5),
                List.of(anchorOf(records.get(0)), anchorOf(records.get(4))));
        assertTrue(r.valid(), r.problem());
        assertEquals(3, r.checkedRecords());
    }

    // Mutation-driven tests: the checks are layered, so a test that only asserts valid() == false
    // cannot tell which defence fired. These assert the reason, the position and accept()'s result.

    /** Index of the first record accept() rejects, or -1: the caller stops streaming there. */
    private int firstRejected(List<SignedRecord> records, List<AuditAnchor> anchors) {
        NodeVerifier v = new NodeVerifier(NODE, keys, anchors);
        for (int i = 0; i < records.size(); i++) {
            if (!v.accept(records.get(i))) {
                return i;
            }
        }
        return -1;
    }

    /** Feeds every record, ignoring accept()'s result, as a stream that does not stop early would. */
    private NodeVerifier.Result verifyAll(List<SignedRecord> records, List<AuditAnchor> anchors) {
        NodeVerifier v = new NodeVerifier(NODE, keys, anchors);
        records.forEach(v::accept);
        return v.finish();
    }

    @Test
    void acceptTellsTheCallerWhenToStopStreaming() {
        List<SignedRecord> records = chain(3);
        records.set(1, new SignedRecord(records.get(1).record(), null, null));
        NodeVerifier v = new NodeVerifier(NODE, keys, List.of());

        assertTrue(v.accept(records.get(0)));
        assertFalse(v.accept(records.get(1)));
        assertFalse(v.accept(records.get(2)), "stays invalid after the first failure");
    }

    @Test
    void firstFailureIsKeptWhenMoreRecordsFollow() {
        List<SignedRecord> records = chain(4);
        records.set(1, new SignedRecord(records.get(1).record(), null, null));

        NodeVerifier.Result r = verifyAll(records, List.of());

        assertEquals(1, r.firstInvalidSequence());
        assertEquals("record has no MAC", r.problem());
        assertEquals(1, r.checkedRecords());
    }

    @Test
    void recordDeletedInTheMiddleBreaksTheChain() {
        List<SignedRecord> records = new ArrayList<>(chain(4));
        records.remove(1);

        NodeVerifier.Result r = verifyAll(records, List.of());

        assertEquals(1, firstRejected(records, List.of()), "stops at the record after the gap");
        assertEquals(2, r.firstInvalidSequence());
        assertEquals("hash chain broken", r.problem());
    }

    @Test
    void recordEditedWithoutTheKeyBreaksTheChain() {
        // An attacker with database access changes the content but cannot recompute hash and MAC.
        List<SignedRecord> records = chain(3);
        SignedRecord original = records.get(1);
        AuditRecord rec = original.record();
        AuditRecord edited = new AuditRecord(rec.getSequence(), rec.getTimestampMillis(), rec.getClientIp(),
                rec.getMethod(), "/innocent", rec.getRoutePrefix(), rec.getDecision(), rec.getHttpStatus(),
                rec.getPreviousHash(), rec.getHash());
        records.set(1, new SignedRecord(edited, original.keyId(), original.mac()));

        NodeVerifier.Result r = verifyAll(records, List.of());

        assertEquals(1, r.firstInvalidSequence());
        assertEquals("hash chain broken", r.problem());
    }

    @Test
    void chainStartingAtZeroMustStartFromGenesis() {
        AuditRecord first = AuditRecord.create(0, 1L, "10.0.0.1", "GET", "/", "r", "ALLOW", 200, "b".repeat(64));

        NodeVerifier.Result r = verifyAll(List.of(sign(first)), List.of());

        assertEquals(0, r.firstInvalidSequence());
        assertEquals("hash chain broken", r.problem());
    }

    @Test
    void recordSignedWithAnUnknownKeyIsRejected() {
        AuditKeys other = new AuditKeys("another-audit-key-0123456789abcdef", List.of());
        List<SignedRecord> records = chain(2);
        AuditRecord rec = records.get(1).record();
        AuditKeys.Signature s = other.sign(AuditKeys.recordMessage(NODE, rec));
        records.set(1, new SignedRecord(rec, s.keyId(), s.mac()));

        NodeVerifier.Result r = verifyAll(records, List.of());

        assertEquals(1, firstRejected(records, List.of()));
        assertEquals(1, r.firstInvalidSequence());
        assertEquals("invalid MAC, or signed with a key that is not configured", r.problem());
    }

    @Test
    void recordDifferentFromItsAnchorNamesTheReason() {
        List<SignedRecord> records = chain(3);
        AuditAnchor wrong = AuditAnchor.create(NODE, 1, "b".repeat(64), 1L, keys);

        NodeVerifier.Result r = verifyAll(records, List.of(wrong));

        assertEquals(1, firstRejected(records, List.of(wrong)));
        assertEquals("record differs from its anchor", r.problem());
    }

    @Test
    void conflictingAnchorsNameTheReason() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(1));
        AuditAnchor b = AuditAnchor.create(NODE, 1, "c".repeat(64), 2L, keys);

        NodeVerifier.Result r = verifyAll(records, List.of(a, b));

        assertEquals(1, r.firstInvalidSequence());
        assertEquals("conflicting anchors for record #1", r.problem());
    }

    @Test
    void firstForgedAnchorIsReported() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(2));
        AuditAnchor forged5 = new AuditAnchor(NODE, 5, a.hash(), a.timestampMillis(), a.keyId(), a.mac());
        AuditAnchor forged9 = new AuditAnchor(NODE, 9, a.hash(), a.timestampMillis(), a.keyId(), a.mac());

        NodeVerifier.Result r = verifyAll(records, List.of(forged5, forged9));

        assertEquals(5, r.firstInvalidSequence());
        assertEquals("anchor #5 is not authentic", r.problem());
    }

    @Test
    void laterConflictDoesNotHideAnEarlierForgery() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(2));
        AuditAnchor forged = new AuditAnchor(NODE, 5, a.hash(), a.timestampMillis(), a.keyId(), a.mac());
        AuditAnchor b = AuditAnchor.create(NODE, 1, "c".repeat(64), 2L, keys);

        NodeVerifier.Result r = verifyAll(records, List.of(forged, anchorOf(records.get(1)), b));

        assertEquals("anchor #5 is not authentic", r.problem());
    }

    @Test
    void identicalDuplicateAnchorsAreNotAConflict() {
        List<SignedRecord> records = chain(3);
        AuditAnchor a = anchorOf(records.get(1));

        NodeVerifier.Result r = verifyAll(records, List.of(a, a));

        assertTrue(r.valid(), r.problem());
    }
}
