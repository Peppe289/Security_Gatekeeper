package io.github.peppe289.security_gatekeeper.core.audit;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;

/**
 * Head of an append-only, hash-linked audit chain.
 *
 * <p>Only the chain head (next sequence number and last hash) is kept in
 * memory: records are handed to the caller, which persists them. A chain can
 * be resumed from its last persisted record after a restart.
 *
 * <p>Not thread-safe: a single writer thread owns the chain.
 */
public final class AuditChain {

    /** {@code previousHash} of the very first record. */
    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private /*@ spec_public @*/ long nextSequence;
    private /*@ spec_public @*/ String headHash;

    //@ public invariant nextSequence >= 0;
    //@ public invariant headHash != null && headHash.length() == Sha256.HEX_LENGTH;

    /** Starts a new chain from the genesis hash. */
    /*@ public normal_behavior
      @   ensures nextSequence == 0 && headHash == GENESIS_HASH;
      @*/
    public AuditChain() {
        this.nextSequence = 0;
        this.headHash = GENESIS_HASH;
    }

    /**
     * Resumes a chain whose last record has sequence {@code nextSequence - 1}
     * and hash {@code headHash}.
     *
     * @throws IllegalArgumentException if {@code nextSequence < 0} or {@code headHash} is not a digest
     */
    /*@ public normal_behavior
      @   requires nextSequence >= 0 && Sha256.isHexDigest(headHash);
      @   ensures this.nextSequence == nextSequence && this.headHash == headHash;
      @ also public exceptional_behavior
      @   requires nextSequence < 0 || !Sha256.isHexDigest(headHash);
      @   signals_only IllegalArgumentException;
      @*/
    public AuditChain(long nextSequence, String headHash) {
        if (nextSequence < 0) {
            throw new IllegalArgumentException("nextSequence must be >= 0");
        }
        if (!Sha256.isHexDigest(headHash)) {
            throw new IllegalArgumentException("headHash must be a SHA-256 hex digest");
        }
        this.nextSequence = nextSequence;
        this.headHash = headHash;
    }

    /**
     * Creates the next record, linked to the current head, and advances the head.
     */
    /*@ public normal_behavior
      @   requires nextSequence < Long.MAX_VALUE;
      @   requires clientIp != null && method != null && path != null;
      @   requires routePrefix != null && decision != null;
      @   assignable nextSequence, headHash;
      @   ensures \result.sequence == \old(nextSequence);
      @   ensures \result.previousHash == \old(headHash);
      @   ensures headHash == \result.hash;
      @   ensures nextSequence == \old(nextSequence) + 1;
      @*/
    public AuditRecord append(long timestampMillis, String clientIp, String method, String path,
                              String routePrefix, String decision, int httpStatus) {
        AuditRecord rec = AuditRecord.create(nextSequence, timestampMillis, clientIp, method, path,
                routePrefix, decision, httpStatus, headHash);
        nextSequence++;
        headHash = rec.getHash();
        return rec;
    }

    //@ ensures \result == nextSequence;
    public /*@ pure @*/ long nextSequence() {
        return nextSequence;
    }

    //@ ensures \result == headHash;
    public /*@ pure @*/ String headHash() {
        return headHash;
    }
}
