package io.github.peppe289.security_gatekeeper.audit;

/**
 * Signed checkpoint of a node's chain head, kept outside the database.
 *
 * <p>The chain alone cannot reveal that its latest records were deleted: what
 * remains is still a valid, shorter chain. An anchor states that record
 * {@code sequence} existed with hash {@code hash}; verification fails if that
 * record is missing or different. Anchors are signed with an audit key, so
 * they cannot be forged either.
 *
 * <p>Stored one per line as tab-separated values:
 * {@code v1, nodeId, sequence, hash, timestampMillis, keyId, mac}.
 */
public record AuditAnchor(String nodeId, long sequence, String hash, long timestampMillis, String keyId,
                          String mac) {

    private static final String VERSION = "v1";
    private static final String DOMAIN = "gatekeeper-audit-anchor-v1|";
    private static final int FIELDS = 7;

    /** Creates an anchor for record {@code sequence}/{@code hash} of {@code nodeId}, signed with the active key. */
    static AuditAnchor create(String nodeId, long sequence, String hash, long timestampMillis, AuditKeys keys) {
        AuditKeys.Signature signature = keys.sign(message(nodeId, sequence, hash, timestampMillis));
        return new AuditAnchor(nodeId, sequence, hash, timestampMillis, signature.keyId(), signature.mac());
    }

    /** @return {@code true} iff the anchor was signed by one of {@code keys} and has not been altered */
    boolean isAuthentic(AuditKeys keys) {
        return keys.verify(keyId, message(nodeId, sequence, hash, timestampMillis), mac);
    }

    String toLine() {
        return String.join("\t", VERSION, nodeId, Long.toString(sequence), hash, Long.toString(timestampMillis),
                keyId, mac);
    }

    /**
     * Parses a line written by {@link #toLine()}.
     *
     * @throws IllegalArgumentException if the line is malformed
     */
    static AuditAnchor parse(String line) {
        String[] f = line.split("\t", -1);
        if (f.length != FIELDS || !VERSION.equals(f[0])) {
            throw new IllegalArgumentException("malformed anchor line");
        }
        try {
            return new AuditAnchor(f[1], Long.parseLong(f[2]), f[3], Long.parseLong(f[4]), f[5], f[6]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("malformed anchor line", e);
        }
    }

    private static String message(String nodeId, long sequence, String hash, long timestampMillis) {
        return DOMAIN + nodeId + "|" + sequence + "|" + hash + "|" + timestampMillis;
    }
}
