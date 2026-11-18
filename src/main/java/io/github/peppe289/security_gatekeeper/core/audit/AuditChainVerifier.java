package io.github.peppe289.security_gatekeeper.core.audit;

/**
 * Incremental, constant-memory verifier: records are fed one at a time in
 * sequence order (e.g. streamed from a database cursor).
 *
 * <p>A record is rejected if its sequence number is not consecutive, if it
 * does not point to the previous record's hash (or to the anchor, for the
 * first one), or if its own hash does not match its content. After the first
 * failure the verifier stays invalid.
 */
public final class AuditChainVerifier {

    private /*@ spec_public @*/ String expectedPrevious;
    private /*@ spec_public @*/ long expectedSequence;
    private /*@ spec_public @*/ boolean started;
    private /*@ spec_public @*/ long checked;
    private /*@ spec_public @*/ long firstInvalidSequence;

    //@ public invariant expectedPrevious != null;
    //@ public invariant checked >= 0;
    //@ public invariant firstInvalidSequence >= -1;

    /**
     * @param anchorHash hash the first record must point to
     *                   ({@link AuditChain#GENESIS_HASH} for a chain starting at sequence 0)
     */
    /*@ public normal_behavior
      @   requires anchorHash != null;
      @   ensures expectedPrevious == anchorHash && checked == 0 && firstInvalidSequence == -1 && !started;
      @ also public exceptional_behavior
      @   requires anchorHash == null;
      @   signals_only IllegalArgumentException;
      @*/
    public AuditChainVerifier(/*@ nullable @*/ String anchorHash) {
        if (anchorHash == null) {
            throw new IllegalArgumentException("anchorHash must not be null");
        }
        this.expectedPrevious = anchorHash;
        this.firstInvalidSequence = -1;
    }

    /**
     * @return {@code true} if the chain is still valid after this record
     */
    /*@ public normal_behavior
      @   requires rec != null;
      @   requires rec.sequence < Long.MAX_VALUE && checked < Long.MAX_VALUE;
      @   ensures \result <==> firstInvalidSequence == -1;
      @   ensures \old(firstInvalidSequence) != -1 ==> !\result;
      @*/
    public boolean accept(AuditRecord rec) {
        if (firstInvalidSequence != -1) {
            return false;
        }
        boolean sequenceOk = !started || rec.getSequence() == expectedSequence;
        if (!sequenceOk || !rec.getPreviousHash().equals(expectedPrevious) || !rec.isHashValid()) {
            firstInvalidSequence = rec.getSequence();
            return false;
        }
        started = true;
        expectedSequence = rec.getSequence() + 1;
        expectedPrevious = rec.getHash();
        checked++;
        return true;
    }

    /*@ public normal_behavior
      @   ensures \result <==> firstInvalidSequence == -1;
      @*/
    public /*@ pure @*/ boolean isValid() {
        return firstInvalidSequence == -1;
    }

    /** @return number of records verified successfully */
    /*@ public normal_behavior
      @   ensures \result == checked;
      @*/
    public /*@ pure @*/ long checkedCount() {
        return checked;
    }

    /** @return sequence number of the first invalid record, or {@code -1} */
    /*@ public normal_behavior
      @   ensures \result == firstInvalidSequence;
      @*/
    public /*@ pure @*/ long firstInvalidSequence() {
        return firstInvalidSequence;
    }
}
