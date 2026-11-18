package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.SignedRecord;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChainVerifier;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import java.util.Collection;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * Verifies one node's chain, fed record by record in sequence order, against
 * the node's anchors. A record is rejected if:
 * <ul>
 *   <li>it breaks the hash chain (content changed, record inserted, removed or
 *       reordered: see {@link AuditChainVerifier});</li>
 *   <li>it has no valid MAC (rewritten without the key, signature stripped, or
 *       signed with a key that is not configured);</li>
 *   <li>it differs from an anchor with the same sequence number.</li>
 * </ul>
 * After the last record, {@link #finish()} fails if an anchor refers to a
 * record beyond the end of the stored chain, i.e. the latest records were deleted.
 *
 * <p>The first stored record anchors the hash chain: {@code GENESIS} for a
 * complete chain, or its own previous hash if older rows were purged by a
 * retention policy. Anchors older than that record are ignored for the same reason.
 */
final class NodeVerifier {

    /** Outcome for one node; {@code problem} is {@code null} when the chain is valid. */
    record Result(String nodeId, boolean valid, long checkedRecords, long firstInvalidSequence, String problem,
                  int anchors) {
    }

    private final String nodeId;
    private final AuditKeys keys;
    private final NavigableMap<Long, AuditAnchor> anchors = new TreeMap<>();

    private AuditChainVerifier chain;
    private long lastSequence = -1;
    private long checked;
    private long firstInvalidSequence = -1;
    private String problem;

    NodeVerifier(String nodeId, AuditKeys keys, Collection<AuditAnchor> nodeAnchors) {
        this.nodeId = nodeId;
        this.keys = keys;
        for (AuditAnchor a : nodeAnchors) {
            if (problem == null && !a.isAuthentic(keys)) {
                fail(a.sequence(), "anchor #" + a.sequence() + " is not authentic");
            }
            AuditAnchor previous = anchors.put(a.sequence(), a);
            if (problem == null && previous != null && !previous.hash().equals(a.hash())) {
                fail(a.sequence(), "conflicting anchors for record #" + a.sequence());
            }
        }
    }

    /** @return {@code true} while the chain is still valid */
    boolean accept(SignedRecord signed) {
        if (problem != null) {
            return false;
        }
        AuditRecord rec = signed.record();
        long seq = rec.getSequence();
        if (chain == null) {
            chain = new AuditChainVerifier(seq == 0 ? AuditChain.GENESIS_HASH : rec.getPreviousHash());
        }
        if (!chain.accept(rec)) {
            return fail(seq, "hash chain broken");
        }
        if (signed.mac() == null) {
            return fail(seq, "record has no MAC");
        }
        if (!keys.verify(signed.keyId(), AuditKeys.recordMessage(nodeId, rec), signed.mac())) {
            return fail(seq, "invalid MAC, or signed with a key that is not configured");
        }
        AuditAnchor anchor = anchors.get(seq);
        if (anchor != null && !anchor.hash().equals(rec.getHash())) {
            return fail(seq, "record differs from its anchor");
        }
        lastSequence = seq;
        checked++;
        return true;
    }

    /** Checks the anchors past the end of the stream, then returns the outcome. */
    Result finish() {
        if (problem == null && !anchors.isEmpty() && anchors.lastKey() > lastSequence) {
            if (chain == null) {
                fail(anchors.firstKey(), "chain is missing, but anchored up to #" + anchors.lastKey());
            } else {
                fail(lastSequence + 1, "records missing at the end of the chain (anchored up to #"
                        + anchors.lastKey() + ")");
            }
        }
        return new Result(nodeId, problem == null, checked, firstInvalidSequence, problem, anchors.size());
    }

    private boolean fail(long sequence, String reason) {
        firstInvalidSequence = sequence;
        problem = reason;
        return false;
    }
}
