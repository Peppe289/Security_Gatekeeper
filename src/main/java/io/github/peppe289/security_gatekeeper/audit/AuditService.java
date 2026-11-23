package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.SignedRecord;
import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.SmartLifecycle;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

/**
 * Asynchronous, batched audit trail.
 *
 * <p>The request thread only enqueues an {@link AuditEvent} (non-blocking
 * {@code offer}): hashing and database I/O happen on a single background
 * writer thread, which owns the {@link AuditChain} and therefore needs no
 * locking. If the database is unavailable the current batch is retried with
 * backoff; after a sequence collision the chain is resumed from the stored
 * head. If the queue overflows, new events are dropped and counted rather
 * than slowing down proxied traffic.
 *
 * <p>Every record is signed with an {@link AuditKeys audit key}, and at most
 * once per {@code gateway.audit.anchor-interval} the writer stores a signed
 * {@link AuditAnchor} of the chain head outside the database, so that
 * verification also detects records deleted from the end of a chain.
 */
@Service
public class AuditService implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    static final int MAX_PATH_LENGTH = 512;
    static final int MAX_METHOD_LENGTH = 16;
    static final int MAX_IP_LENGTH = 45;
    static final int MAX_PREFIX_LENGTH = 63;
    private static final Duration INITIAL_RETRY_BACKOFF = Duration.ofMillis(200);
    private static final Duration MAX_RETRY_BACKOFF = Duration.ofSeconds(30);

    private final AuditRepository repository;
    private final AuditKeys keys;
    private final AuditAnchorStore anchors;
    private final Clock clock;
    private final String nodeId;
    private final int batchSize;
    private final Duration flushInterval;
    private final Duration anchorInterval;
    private final BlockingQueue<AuditEvent> queue;

    private final Map<AccessDecision, LongAdder> counters;
    private final LongAdder dropped = new LongAdder();
    private final LongAdder persisted = new LongAdder();

    private volatile boolean running;
    private volatile Thread writer;
    // owned by the writer thread
    private AuditChain chain;
    private AuditRecord lastPersisted;
    private long lastAnchoredSequence = -1;
    private Instant nextAnchorAt = Instant.MIN;

    /** What the request thread records: no hash yet. */
    record AuditEvent(long timestampMillis, String clientIp, String method, String path,
                      String routePrefix, AccessDecision decision, int httpStatus) {
    }

    public record AuditStats(long totalRequests, Map<String, Long> byDecision, long persisted,
                             long dropped, int queued) {
    }

    /**
     * Result of verifying every node's chain.
     *
     * @param brokenNode           node whose chain is broken, or {@code null}
     * @param firstInvalidSequence first invalid record in {@code brokenNode}, or {@code -1}
     * @param problem              why verification failed, or {@code null} if valid
     * @param anchors              anchors read from outside the database and checked
     */
    public record IntegrityReport(boolean valid, long checkedRecords, int nodes, String brokenNode,
                                  long firstInvalidSequence, String problem, int anchors, Instant verifiedAt) {
    }

    public AuditService(AuditRepository repository, AuditKeys keys, AuditAnchorStore anchors, Clock clock,
                        GatewayProperties properties) {
        this.repository = repository;
        this.keys = keys;
        this.anchors = anchors;
        this.clock = clock;
        this.nodeId = properties.nodeId();
        this.batchSize = properties.audit().batchSize();
        this.flushInterval = properties.audit().flushInterval();
        this.anchorInterval = properties.audit().anchorInterval();
        this.queue = new ArrayBlockingQueue<>(properties.audit().queueCapacity());
        Map<AccessDecision, LongAdder> map = new EnumMap<>(AccessDecision.class);
        for (AccessDecision d : AccessDecision.values()) {
            map.put(d, new LongAdder());
        }
        this.counters = Collections.unmodifiableMap(map);
    }

    /** Records one request outcome. Never blocks and never throws. */
    public void record(String clientIp, String method, String path, String routePrefix,
                       AccessDecision decision, int httpStatus) {
        counters.get(decision).increment();
        AuditEvent event = new AuditEvent(clock.millis(), clip(clientIp, MAX_IP_LENGTH),
                clip(method, MAX_METHOD_LENGTH), truncatePath(path), clip(routePrefix, MAX_PREFIX_LENGTH),
                decision, httpStatus);
        if (!queue.offer(event)) {
            dropped.increment();
        }
    }

    public List<AuditRepository.StoredRecord> latest(int limit) {
        return repository.findLatest(Math.max(0, limit));
    }

    /**
     * Verifies every node's chain from the database, against the anchors kept
     * outside it. Expensive: callers should rate-limit it.
     */
    public IntegrityReport verifyAll() {
        Map<String, List<AuditAnchor>> anchorsByNode;
        try {
            anchorsByNode = anchors.loadAll();
        } catch (IOException e) {
            log.error("Audit anchors cannot be read: {}", e.toString());
            return new IntegrityReport(false, 0, 0, null, -1, "anchors cannot be read: " + e.getMessage(), 0,
                    clock.instant());
        }
        // A node with anchors but no rows left is checked too: its whole chain was deleted.
        TreeSet<String> nodes = new TreeSet<>(repository.findNodeIds());
        nodes.addAll(anchorsByNode.keySet());
        long checked = 0;
        int anchorCount = 0;
        for (String node : nodes) {
            NodeVerifier.Result result = verifyNode(node, anchorsByNode.getOrDefault(node, List.of()));
            checked += result.checkedRecords();
            anchorCount += result.anchors();
            if (!result.valid()) {
                log.error("Audit chain of node {} is broken at sequence {}: {}", node,
                        result.firstInvalidSequence(), result.problem());
                return new IntegrityReport(false, checked, nodes.size(), node, result.firstInvalidSequence(),
                        result.problem(), anchorCount, clock.instant());
            }
        }
        return new IntegrityReport(true, checked, nodes.size(), null, -1, null, anchorCount, clock.instant());
    }

    /** Verifies one node's chain against its anchors in the anchor directory. */
    NodeVerifier.Result verifyNode(String node) throws IOException {
        return verifyNode(node, anchors.loadAll().getOrDefault(node, List.of()));
    }

    private NodeVerifier.Result verifyNode(String node, List<AuditAnchor> nodeAnchors) {
        NodeVerifier verifier = new NodeVerifier(node, keys, nodeAnchors);
        repository.streamChain(node, verifier::accept);
        return verifier.finish();
    }

    public AuditStats stats() {
        Map<String, Long> byDecision = new LinkedHashMap<>();
        long total = 0;
        for (Map.Entry<AccessDecision, LongAdder> e : counters.entrySet()) {
            long v = e.getValue().sum();
            byDecision.put(e.getKey().name(), v);
            total += v;
        }
        return new AuditStats(total, Collections.unmodifiableMap(byDecision), persisted.sum(), dropped.sum(), queue.size());
    }

    // ---------------------------------------------------------------- writer lifecycle

    @Override
    public void start() {
        chain = repository.findHead(nodeId)
                .map(h -> new AuditChain(h.lastSequence() + 1, h.lastHash()))
                .orElseGet(AuditChain::new);
        log.info("Audit chain for node '{}' resumed at sequence {} (signing key {})", nodeId,
                chain.nextSequence(), keys.activeKeyId());
        if (anchors.isPersistent()) {
            try {
                anchors.init();
            } catch (IOException e) {
                log.error("Audit anchor directory cannot be created: {}", e.toString());
            }
        } else {
            log.warn("gateway.audit.anchor-dir is not set: audit anchors are written to the log only, so "
                    + "verification cannot detect records deleted from the end of a chain");
        }
        running = true;
        Thread t = new Thread(this::writeLoop, "audit-writer");
        t.setDaemon(true);
        writer = t;
        t.start();
    }

    @Override
    public void stop() {
        running = false;
        Thread t = writer;
        if (t != null) {
            t.interrupt();
            try {
                t.join(Duration.ofSeconds(10).toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        writer = null;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    /**
     * Below the web server's phases: Spring starts lifecycle beans in ascending phase order and
     * stops them in descending order, so the writer is running before the server accepts the
     * first request, and stops only after graceful shutdown has let in-flight requests finish
     * and the server has stopped. Their events are then flushed by {@link #stop()}.
     */
    @Override
    public int getPhase() {
        return WebServerApplicationContext.START_STOP_LIFECYCLE_PHASE - 1;
    }

    private void writeLoop() {
        List<AuditEvent> events = new ArrayList<>(batchSize);
        while (running || !queue.isEmpty()) {
            try {
                if (queue.drainTo(events, batchSize) == 0) {
                    AuditEvent first = queue.poll(flushInterval.toMillis(), TimeUnit.MILLISECONDS);
                    if (first != null) {
                        events.add(first);
                        queue.drainTo(events, batchSize - 1);
                    }
                }
            } catch (InterruptedException e) {
                // shutdown requested: the loop condition drains what is left
            }
            if (!events.isEmpty()) {
                persist(events);
                events.clear();
            }
            anchorIfDue(false);
        }
        anchorIfDue(true);
        log.info("Audit writer stopped; chain head at sequence {}", chain.nextSequence());
    }

    private void persist(List<AuditEvent> events) {
        List<SignedRecord> records = appendToChain(events);
        Duration backoff = INITIAL_RETRY_BACKOFF;
        boolean collided = false;
        while (true) {
            try {
                if (collided) {
                    if (repository.contains(nodeId, records.get(records.size() - 1).record())) {
                        // A previous attempt was committed but reported as failed (e.g. connection lost on commit).
                        log.warn("Audit batch of {} records had already been persisted", records.size());
                        markPersisted(records);
                        return;
                    }
                    // Someone else extended this node's chain: continue from the stored head.
                    chain = repository.findHead(nodeId)
                            .map(h -> new AuditChain(h.lastSequence() + 1, h.lastHash()))
                            .orElseGet(AuditChain::new);
                    records = appendToChain(events);
                    collided = false;
                }
                repository.insertBatch(nodeId, records);
                markPersisted(records);
                return;
            } catch (DuplicateKeyException ex) {
                log.error("Audit sequence collision for node '{}': is another instance running with the same "
                        + "gateway.node-id? Resynchronizing the chain", nodeId);
                collided = true;
            } catch (RuntimeException ex) {
                log.warn("Audit batch of {} records not persisted ({}); retrying in {}",
                        records.size(), ex.getClass().getSimpleName(), backoff);
            }
            if (!sleep(backoff)) {
                log.error("Shutdown before the batch could be persisted: {} audit records lost", records.size());
                return;
            }
            backoff = backoff.multipliedBy(2);
            if (backoff.compareTo(MAX_RETRY_BACKOFF) > 0) {
                backoff = MAX_RETRY_BACKOFF;
            }
        }
    }

    private List<SignedRecord> appendToChain(List<AuditEvent> events) {
        List<SignedRecord> records = new ArrayList<>(events.size());
        for (AuditEvent e : events) {
            AuditRecord rec = chain.append(e.timestampMillis(), e.clientIp(), e.method(), e.path(), e.routePrefix(),
                    e.decision().name(), e.httpStatus());
            AuditKeys.Signature signature = keys.sign(AuditKeys.recordMessage(nodeId, rec));
            records.add(new SignedRecord(rec, signature.keyId(), signature.mac()));
        }
        return records;
    }

    private void markPersisted(List<SignedRecord> records) {
        persisted.add(records.size());
        lastPersisted = records.get(records.size() - 1).record();
    }

    /**
     * Anchors the last persisted record if the chain advanced since the previous anchor and
     * {@code anchorInterval} elapsed (or {@code force}, on shutdown). Only persisted records are
     * anchored, so an anchor never refers to a record that is not in the database.
     */
    private void anchorIfDue(boolean force) {
        AuditRecord head = lastPersisted;
        Instant now = clock.instant();
        if (head == null || head.getSequence() <= lastAnchoredSequence || (!force && now.isBefore(nextAnchorAt))) {
            return;
        }
        nextAnchorAt = now.plus(anchorInterval);
        try {
            anchors.append(AuditAnchor.create(nodeId, head.getSequence(), head.getHash(), now.toEpochMilli(), keys));
            lastAnchoredSequence = head.getSequence();
        } catch (IOException | RuntimeException e) {
            log.error("Audit anchor for sequence {} not written ({}); retrying in {}", head.getSequence(),
                    e.toString(), anchorInterval);
        }
    }

    private boolean sleep(Duration d) {
        if (!running) {
            return false;
        }
        try {
            Thread.sleep(d.toMillis());
            return true;
        } catch (InterruptedException e) {
            return false;
        }
    }

    private static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static String truncatePath(String path) {
        if (path == null) {
            return "";
        }
        return path.length() <= MAX_PATH_LENGTH ? path : path.substring(0, MAX_PATH_LENGTH) + "...";
    }
}
