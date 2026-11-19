package io.github.peppe289.security_gatekeeper.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.audit.AuditService.AuditStats;
import io.github.peppe289.security_gatekeeper.audit.AuditService.IntegrityReport;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Caching and rate limiting of the dashboard read model, with a mocked audit service and clock. */
@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");
    private static final AuditStats STATS = new AuditStats(3, Map.of("ALLOW", 3L), 3, 0, 0);

    @Mock
    private AuditService audit;
    @Mock
    private RateLimiterService rateLimiter;
    @Mock
    private Clock clock;

    private DashboardService dashboard;

    @BeforeEach
    void setUp() {
        dashboard = new DashboardService(audit, rateLimiter, clock, TestProperties.defaults());
    }

    private static IntegrityReport report(Instant at) {
        return new IntegrityReport(true, 3, 1, null, -1, null, 1, at);
    }

    @Test
    void firstSnapshotQueriesEverySource() {
        when(clock.instant()).thenReturn(T0);
        when(audit.stats()).thenReturn(STATS);
        when(audit.latest(TestProperties.RECENT_ROWS)).thenReturn(List.of());
        when(rateLimiter.trackedClients()).thenReturn(7);

        DashboardService.Snapshot snapshot = dashboard.snapshot();

        assertEquals(T0, snapshot.generatedAt());
        assertSame(STATS, snapshot.stats());
        assertEquals(7, snapshot.trackedClients());
    }

    @Test
    void snapshotIsServedFromCacheUntilStatsRefreshElapses() {
        Instant justBefore = T0.plus(TestProperties.STATS_REFRESH).minusMillis(1);
        Instant expired = T0.plus(TestProperties.STATS_REFRESH);
        // One read to build the first snapshot, one per freshness check, one to build the next.
        when(clock.instant()).thenReturn(T0, justBefore, expired);
        when(audit.stats()).thenReturn(STATS);

        DashboardService.Snapshot first = dashboard.snapshot();
        DashboardService.Snapshot cached = dashboard.snapshot();
        DashboardService.Snapshot recomputed = dashboard.snapshot();

        assertSame(first, cached);
        assertNotSame(first, recomputed);
        assertEquals(expired, recomputed.generatedAt());
        verify(audit, times(2)).stats();
    }

    @Test
    void noIntegrityReportBeforeTheFirstVerification() {
        assertNull(dashboard.lastIntegrity());
    }

    @Test
    void verificationRunsOnDemandAndIsRemembered() {
        IntegrityReport report = report(T0);
        when(audit.verifyAll()).thenReturn(report);

        DashboardService.VerifyResult result = dashboard.verify();

        assertTrue(result.fresh());
        assertSame(report, result.report());
        assertEquals(Duration.ZERO, result.retryIn());
        assertSame(report, dashboard.lastIntegrity());
    }

    @Test
    void verificationWithinTheCooldownReturnsTheLastReportAndTheWait() {
        when(audit.verifyAll()).thenReturn(report(T0));
        dashboard.verify();
        when(clock.instant()).thenReturn(T0.plusSeconds(10));

        DashboardService.VerifyResult second = dashboard.verify();

        assertFalse(second.fresh());
        assertEquals(TestProperties.VERIFY_COOLDOWN.minusSeconds(10), second.retryIn());
        // The expensive full verification ran only once.
        verify(audit, times(1)).verifyAll();
    }

    @Test
    void verificationRunsAgainOnceTheCooldownHasElapsed() {
        IntegrityReport later = report(T0.plus(TestProperties.VERIFY_COOLDOWN));
        when(audit.verifyAll()).thenReturn(report(T0), later);
        dashboard.verify();
        when(clock.instant()).thenReturn(T0.plus(TestProperties.VERIFY_COOLDOWN));

        DashboardService.VerifyResult second = dashboard.verify();

        assertTrue(second.fresh());
        assertSame(later, second.report());
        verify(audit, times(2)).verifyAll();
    }
}
