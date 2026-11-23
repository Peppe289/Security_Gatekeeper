package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.ChainHead;
import io.github.peppe289.security_gatekeeper.audit.AuditRepository.SignedRecord;
import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.audit.AuditChain;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DuplicateKeyException;

/**
 * Asynchronous audit writer, with the repository and the anchor store mocked.
 *
 * <p>Tests that start the writer thread wait for its effects with Mockito's
 * {@code timeout(...)} instead of fixed sleeps, so they stay fast and not flaky.
 */
class AuditServiceTest {

    private static final String NODE = "node-test";
    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");
    private static final String STORED_HASH = "a".repeat(64);
    private static final long WAIT_MS = 5_000;

    private final AuditRepository repository = mock(AuditRepository.class);
    private final AuditAnchorStore anchors = mock(AuditAnchorStore.class);
    private final AuditKeys keys = new AuditKeys(TestProperties.HMAC_KEY, List.of());
    private final Clock clock = Clock.fixed(T0, ZoneOffset.UTC);

    private AuditService service(int queueCapacity) {
        GatewayProperties properties = TestProperties.with(new GatewayProperties.Audit(queueCapacity, 500,
                Duration.ofMillis(10), TestProperties.HMAC_KEY, List.of(), null, Duration.ofSeconds(60)));
        return new AuditService(repository, keys, anchors, clock, properties);
    }

    private static void allow(AuditService audit, String path) {
        audit.record("10.0.0.1", "GET", path, "svc", AccessDecision.ALLOW, 200);
    }

    /** Every record passed to {@code insertBatch}, in call order. */
    @SuppressWarnings("unchecked")
    private List<AuditRecord> inserted(int calls) {
        ArgumentCaptor<List<SignedRecord>> batches = ArgumentCaptor.forClass(List.class);
        verify(repository, timeout(WAIT_MS).times(calls)).insertBatch(eq(NODE), batches.capture());
        List<AuditRecord> records = new ArrayList<>();
        batches.getAllValues().forEach(b -> b.forEach(s -> records.add(s.record())));
        return records;
    }

    /** Without the writer thread: the request-side API only. */
    @Nested
    class RequestSide {

        @Test
        void outcomesAreCountedPerDecision() {
            AuditService audit = service(100);
            allow(audit, "/a");
            allow(audit, "/b");
            audit.record("10.0.0.1", "GET", "/c", "svc", AccessDecision.RATE_LIMITED, 429);

            AuditService.AuditStats stats = audit.stats();

            assertEquals(3, stats.totalRequests());
            assertEquals(2L, stats.byDecision().get("ALLOW"));
            assertEquals(1L, stats.byDecision().get("RATE_LIMITED"));
            assertEquals(3, stats.queued());
            assertEquals(0, stats.persisted());
        }

        @Test
        void fullQueueDropsAndCountsNewEvents() {
            AuditService audit = service(2);
            allow(audit, "/a");
            allow(audit, "/b");
            allow(audit, "/c");

            AuditService.AuditStats stats = audit.stats();

            assertEquals(1, stats.dropped());
            assertEquals(2, stats.queued());
            assertEquals(3, stats.totalRequests(), "dropped requests are still counted");
        }

        @Test
        void unreadableAnchorsFailVerification() throws IOException {
            when(anchors.loadAll()).thenThrow(new IOException("disk gone"));

            AuditService.IntegrityReport report = service(10).verifyAll();

            assertFalse(report.valid());
            assertTrue(report.problem().startsWith("anchors cannot be read"), report.problem());
        }

        @Test
        void phaseIsBelowTheWebServerSoTheWriterOutlivesIt() {
            // Regression guard for the shutdown bug: see AuditShutdownIntegrationTest.
            assertTrue(service(10).getPhase() < WebServerApplicationContext.START_STOP_LIFECYCLE_PHASE);
        }
    }

    /** With the writer thread running. */
    @Nested
    class Writer {

        private AuditService audit;

        @BeforeEach
        void setUp() {
            audit = service(100);
        }

        @AfterEach
        void stopWriter() {
            audit.stop();
        }

        @Test
        void lifecycleReportsRunningState() {
            assertFalse(audit.isRunning());
            audit.start();
            assertTrue(audit.isRunning());
            audit.stop();
            assertFalse(audit.isRunning());
        }

        @Test
        void newChainStartsFromGenesis() {
            audit.start();
            allow(audit, "/a");

            AuditRecord first = inserted(1).get(0);

            assertEquals(0, first.getSequence());
            assertEquals(AuditChain.GENESIS_HASH, first.getPreviousHash());
        }

        @Test
        void existingChainIsResumedFromItsStoredHead() {
            when(repository.findHead(NODE)).thenReturn(Optional.of(new ChainHead(4, STORED_HASH)));
            audit.start();
            allow(audit, "/a");

            AuditRecord next = inserted(1).get(0);

            assertEquals(5, next.getSequence());
            assertEquals(STORED_HASH, next.getPreviousHash());
        }

        @SuppressWarnings("unchecked")
        @Test
        void everyRecordIsSignedWithTheActiveKey() {
            audit.start();
            allow(audit, "/a");

            ArgumentCaptor<List<SignedRecord>> batch = ArgumentCaptor.forClass(List.class);
            verify(repository, timeout(WAIT_MS)).insertBatch(eq(NODE), batch.capture());
            SignedRecord signed = batch.getValue().get(0);

            assertEquals(keys.activeKeyId(), signed.keyId());
            assertTrue(keys.verify(signed.keyId(), AuditKeys.recordMessage(NODE, signed.record()), signed.mac()));
        }

        @Test
        void oversizedFieldsAreClippedAndLongPathsMarked() {
            audit.start();
            audit.record(null, "X".repeat(20), "/" + "p".repeat(599), "svc", AccessDecision.ALLOW, 200);

            AuditRecord rec = inserted(1).get(0);

            assertEquals("", rec.getClientIp());
            assertEquals(AuditService.MAX_METHOD_LENGTH, rec.getMethod().length());
            assertEquals(AuditService.MAX_PATH_LENGTH + 3, rec.getPath().length());
            assertTrue(rec.getPath().endsWith("..."));
        }

        @Test
        void failedBatchIsRetriedUntilTheDatabaseAcceptsIt() {
            doThrow(new DataAccessResourceFailureException("down"))
                    .doNothing()
                    .when(repository).insertBatch(eq(NODE), anyList());
            audit.start();
            allow(audit, "/a");

            List<AuditRecord> attempts = inserted(2);

            assertEquals(attempts.get(0).getHash(), attempts.get(1).getHash(), "the same record is retried");
            assertEquals(1, audit.stats().persisted());
        }

        @Test
        void sequenceCollisionResumesFromTheStoredHead() {
            // Another writer extended this node's chain: our first batch collides with its rows.
            when(repository.findHead(NODE)).thenReturn(Optional.empty(), Optional.of(new ChainHead(9, STORED_HASH)));
            doThrow(new DuplicateKeyException("collision"))
                    .doNothing()
                    .when(repository).insertBatch(eq(NODE), anyList());
            audit.start();
            allow(audit, "/a");

            List<AuditRecord> attempts = inserted(2);

            assertEquals(0, attempts.get(0).getSequence());
            assertEquals(10, attempts.get(1).getSequence());
            assertEquals(STORED_HASH, attempts.get(1).getPreviousHash());
        }

        @Test
        void collidingBatchAlreadyCommittedIsNotWrittenAgain() {
            // The commit succeeded but its acknowledgement was lost: the rows are ours.
            doThrow(new DuplicateKeyException("collision")).when(repository).insertBatch(eq(NODE), anyList());
            when(repository.contains(eq(NODE), any(AuditRecord.class))).thenReturn(true);
            audit.start();
            allow(audit, "/a");

            verify(repository, timeout(WAIT_MS)).contains(eq(NODE), any(AuditRecord.class));
            verify(repository, times(1)).insertBatch(eq(NODE), anyList());
            assertEquals(1, audit.stats().persisted());
        }

        @Test
        void stopFlushesTheQueueAndAnchorsTheLastRecord() throws IOException {
            doNothing().when(repository).insertBatch(eq(NODE), anyList());
            audit.start();
            allow(audit, "/a");
            allow(audit, "/b");
            allow(audit, "/c");

            audit.stop();

            assertEquals(3, audit.stats().persisted());
            ArgumentCaptor<AuditAnchor> anchor = ArgumentCaptor.forClass(AuditAnchor.class);
            verify(anchors, atLeastOnce()).append(anchor.capture());
            AuditAnchor last = anchor.getValue();
            assertEquals(2, last.sequence());
            assertTrue(last.isAuthentic(keys));
        }

        @Test
        void nothingToPersistMeansNoAnchor() throws IOException {
            audit.start();
            audit.stop();

            verify(repository, never()).insertBatch(any(), anyList());
            verify(anchors, never()).append(any());
        }
    }
}
