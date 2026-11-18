package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChainVerifier;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final Clock clock;
    private final String nodeId;
    private final int batchSize;
    private final Duration flushInterval;
    private final BlockingQueue<AuditEvent> queue;

    private final Map<AccessDecision, LongAdder> counters;
    private final LongAdder dropped = new LongAdder();
    private final LongAdder persisted = new LongAdder();

    private volatile boolean running;
    private volatile Thread writer;
    private AuditChain chain; // owned by the writer thread

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
     * @param brokenNode node whose chain is broken, or {@code null}
     * @param firstInvalidSequence first invalid record in {@code brokenNode}, or {@code -1}
     */
    public record IntegrityReport(boolean valid, long checkedRecords, int nodes, String brokenNode,
                                  long firstInvalidSequence, Instant verifiedAt) {
    }

    public AuditService(AuditRepository repository, Clock clock, GatewayProperties properties) {
        this.repository = repository;
        this.clock = clock;
        this.nodeId = properties.nodeId();
        this.batchSize = properties.audit().batchSize();
        this.flushInterval = properties.audit().flushInterval();
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

    /** Verifies every node's chain from the database. Expensive: callers should rate-limit it. */
    public IntegrityReport verifyAll() {
        long checked = 0;
        List<String> nodes = repository.findNodeIds();
        for (String node : nodes) {
            AuditChainVerifier verifier = verifyNode(node);
            checked += verifier.checkedCount();
            if (!verifier.isValid()) {
                log.error("Audit chain of node {} is broken at sequence {}", node, verifier.firstInvalidSequence());
                return new IntegrityReport(false, checked, nodes.size(), node, verifier.firstInvalidSequence(),
                        clock.instant());
            }
        }
        return new IntegrityReport(true, checked, nodes.size(), null, -1, clock.instant());
    }

    AuditChainVerifier verifyNode(String node) {
        AuditChainVerifier[] holder = new AuditChainVerifier[1];
        repository.streamChain(node, rec -> {
            if (holder[0] == null) {
                // The first retained row anchors the verification: GENESIS for a complete chain,
                // or its own previous hash if older rows were purged by a retention policy.
                holder[0] = new AuditChainVerifier(rec.getSequence() == 0 ? AuditChain.GENESIS_HASH : rec.getPreviousHash());
            }
            return holder[0].accept(rec);
        });
        return holder[0] == null ? new AuditChainVerifier(AuditChain.GENESIS_HASH) : holder[0];
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
        log.info("Audit chain for node '{}' resumed at sequence {}", nodeId, chain.nextSequence());
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

    /** Started after the web server is stopped last: pending events are flushed on shutdown. */
    @Override
    public int getPhase() {
        return Integer.MAX_VALUE - 1000;
    }

    private void writeLoop() {
        List<AuditEvent> events = new ArrayList<>(batchSize);
        while (running || !queue.isEmpty()) {
            try {
                if (queue.drainTo(events, batchSize) == 0) {
                    AuditEvent first = queue.poll(flushInterval.toMillis(), TimeUnit.MILLISECONDS);
                    if (first == null) {
                        continue;
                    }
                    events.add(first);
                    queue.drainTo(events, batchSize - 1);
                }
            } catch (InterruptedException e) {
                // shutdown requested: loop condition drains what is left
                continue;
            }
            persist(events);
            events.clear();
        }
        log.info("Audit writer stopped; chain head at sequence {}", chain.nextSequence());
    }

    private void persist(List<AuditEvent> events) {
        List<AuditRecord> records = appendToChain(events);
        Duration backoff = INITIAL_RETRY_BACKOFF;
        boolean collided = false;
        while (true) {
            try {
                if (collided) {
                    if (repository.contains(nodeId, records.get(records.size() - 1))) {
                        // A previous attempt was committed but reported as failed (e.g. connection lost on commit).
                        log.warn("Audit batch of {} records had already been persisted", records.size());
                        persisted.add(records.size());
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
                persisted.add(records.size());
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

    private List<AuditRecord> appendToChain(List<AuditEvent> events) {
        List<AuditRecord> records = new ArrayList<>(events.size());
        for (AuditEvent e : events) {
            records.add(chain.append(e.timestampMillis(), e.clientIp(), e.method(), e.path(), e.routePrefix(),
                    e.decision().name(), e.httpStatus()));
        }
        return records;
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
