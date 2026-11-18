package io.github.peppe289.security_gatekeeper.core.audit;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;

/**
 * Immutable audit entry, cryptographically linked to its predecessor:
 * {@code hash = SHA-256(canonical(fields) + previousHash)}.
 *
 * <p>The canonical form length-prefixes every field ({@code len:value|}), so
 * two different records can never serialize to the same string (e.g.
 * {@code ("a|b","c")} vs {@code ("a","b|c")}).
 */
public final class AuditRecord {

    private final /*@ spec_public @*/ long sequence;
    private final /*@ spec_public @*/ long timestampMillis;
    private final /*@ spec_public @*/ String clientIp;
    private final /*@ spec_public @*/ String method;
    private final /*@ spec_public @*/ String path;
    private final /*@ spec_public @*/ String routePrefix;
    private final /*@ spec_public @*/ String decision;
    private final /*@ spec_public @*/ int httpStatus;
    private final /*@ spec_public @*/ String previousHash;
    private final /*@ spec_public @*/ String hash;

    //@ public invariant sequence >= 0;
    //@ public invariant clientIp != null && method != null && path != null;
    //@ public invariant routePrefix != null && decision != null;
    //@ public invariant previousHash != null && hash != null;

    /**
     * Rebuilds a record with a given hash (e.g. loaded from an export). The
     * hash is <em>not</em> recomputed: use {@link #isHashValid()} to check it.
     *
     * @throws IllegalArgumentException if a field is null or {@code sequence < 0}
     */
    /*@ public normal_behavior
      @   requires sequence >= 0;
      @   requires clientIp != null && method != null && path != null;
      @   requires routePrefix != null && decision != null && previousHash != null && hash != null;
      @   ensures this.sequence == sequence && this.hash == hash && this.previousHash == previousHash;
      @ also public exceptional_behavior
      @   requires sequence < 0 || clientIp == null || method == null || path == null
      @         || routePrefix == null || decision == null || previousHash == null || hash == null;
      @   signals_only IllegalArgumentException;
      @ pure
      @*/
    public AuditRecord(long sequence, long timestampMillis, /*@ nullable @*/ String clientIp, /*@ nullable @*/ String method, /*@ nullable @*/ String path,
                       /*@ nullable @*/ String routePrefix, /*@ nullable @*/ String decision, int httpStatus, /*@ nullable @*/ String previousHash,
                       /*@ nullable @*/ String hash) {
        if (sequence < 0) {
            throw new IllegalArgumentException("sequence must be >= 0");
        }
        if (clientIp == null || method == null || path == null || routePrefix == null
                || decision == null || previousHash == null || hash == null) {
            throw new IllegalArgumentException("audit fields must not be null");
        }
        this.sequence = sequence;
        this.timestampMillis = timestampMillis;
        this.clientIp = clientIp;
        this.method = method;
        this.path = path;
        this.routePrefix = routePrefix;
        this.decision = decision;
        this.httpStatus = httpStatus;
        this.previousHash = previousHash;
        this.hash = hash;
    }

    /** Creates a record whose hash is computed from its content and {@code previousHash}. */
    /*@ public normal_behavior
      @   requires sequence >= 0;
      @   requires clientIp != null && method != null && path != null;
      @   requires routePrefix != null && decision != null && previousHash != null;
      @   ensures \result.sequence == sequence && \result.previousHash == previousHash;
      @   ensures \result.hash.length() == Sha256.HEX_LENGTH;
      @ pure
      @*/
    public static AuditRecord create(long sequence, long timestampMillis, String clientIp, String method,
                                     String path, String routePrefix, String decision, int httpStatus,
                                     String previousHash) {
        String hash = computeHash(sequence, timestampMillis, clientIp, method, path, routePrefix,
                decision, httpStatus, previousHash);
        return new AuditRecord(sequence, timestampMillis, clientIp, method, path, routePrefix,
                decision, httpStatus, previousHash, hash);
    }

    /*@ public normal_behavior
      @   requires clientIp != null && method != null && path != null;
      @   requires routePrefix != null && decision != null && previousHash != null;
      @   ensures \result != null && \result.length() == Sha256.HEX_LENGTH;
      @ pure
      @*/
    //@ skipesc // canonical serialization via StringBuilder (no usable JML specification); covered by AuditRecordTest
    public static String computeHash(long sequence, long timestampMillis, String clientIp, String method,
                                     String path, String routePrefix, String decision, int httpStatus,
                                     String previousHash) {
        StringBuilder sb = new StringBuilder();
        field(sb, Long.toString(sequence));
        field(sb, Long.toString(timestampMillis));
        field(sb, clientIp);
        field(sb, method);
        field(sb, path);
        field(sb, routePrefix);
        field(sb, decision);
        field(sb, Integer.toString(httpStatus));
        field(sb, previousHash);
        return Sha256.hex(sb.toString());
    }

    //@ skipesc // helper of computeHash
    private static void field(StringBuilder sb, String value) {
        sb.append(value.length()).append(':').append(value).append('|');
    }

    /** @return {@code true} iff the stored hash matches the record content */
    /*@ public normal_behavior
      @ pure
      @*/
    public boolean isHashValid() {
        String expected = computeHash(sequence, timestampMillis, clientIp, method, path, routePrefix,
                decision, httpStatus, previousHash);
        return expected.equals(hash);
    }

    /*@ public normal_behavior
      @   ensures \result == sequence;
      @*/
    public /*@ pure @*/ long getSequence() {
        return sequence;
    }

    /*@ public normal_behavior
      @   ensures \result == timestampMillis;
      @*/
    public /*@ pure @*/ long getTimestampMillis() {
        return timestampMillis;
    }

    /*@ public normal_behavior
      @   ensures \result == clientIp;
      @*/
    public /*@ pure @*/ String getClientIp() {
        return clientIp;
    }

    /*@ public normal_behavior
      @   ensures \result == method;
      @*/
    public /*@ pure @*/ String getMethod() {
        return method;
    }

    /*@ public normal_behavior
      @   ensures \result == path;
      @*/
    public /*@ pure @*/ String getPath() {
        return path;
    }

    /*@ public normal_behavior
      @   ensures \result == routePrefix;
      @*/
    public /*@ pure @*/ String getRoutePrefix() {
        return routePrefix;
    }

    /*@ public normal_behavior
      @   ensures \result == decision;
      @*/
    public /*@ pure @*/ String getDecision() {
        return decision;
    }

    /*@ public normal_behavior
      @   ensures \result == httpStatus;
      @*/
    public /*@ pure @*/ int getHttpStatus() {
        return httpStatus;
    }

    /*@ public normal_behavior
      @   ensures \result == previousHash;
      @*/
    public /*@ pure @*/ String getPreviousHash() {
        return previousHash;
    }

    /*@ public normal_behavior
      @   ensures \result == hash;
      @*/
    public /*@ pure @*/ String getHash() {
        return hash;
    }
}
