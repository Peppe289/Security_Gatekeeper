package io.github.peppe289.security_gatekeeper.admin;

import io.github.peppe289.security_gatekeeper.audit.AuditRepository.StoredRecord;
import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.audit.AuditService.AuditStats;
import io.github.peppe289.security_gatekeeper.audit.AuditService.IntegrityReport;
import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Read model for the dashboard. Statistics and recent audit rows are
 * recomputed at most once per {@code gateway.dashboard.stats-refresh}
 * (default 5 s) no matter how many admins reload the page; the full audit
 * verification is run only on demand, at most once per
 * {@code gateway.dashboard.verify-cooldown}.
 */
@Service
public class DashboardService {

    private final AuditService audit;
    private final RateLimiterService rateLimiter;
    private final Clock clock;
    private final Duration statsRefresh;
    private final Duration verifyCooldown;
    private final int recentRows;
    // Separate locks: a long verification must not block page loads that refresh the statistics.
    private final Object snapshotLock = new Object();
    private final Object verifyLock = new Object();

    private volatile Snapshot snapshot;
    private volatile IntegrityReport lastIntegrity;

    public record Snapshot(Instant generatedAt, AuditStats stats, List<StoredRecord> recent, int trackedClients) {
    }

    public record VerifyResult(IntegrityReport report, boolean fresh, Duration retryIn) {
    }

    public DashboardService(AuditService audit, RateLimiterService rateLimiter, Clock clock, GatewayProperties properties) {
        this.audit = audit;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
        this.statsRefresh = properties.dashboard().statsRefresh();
        this.verifyCooldown = properties.dashboard().verifyCooldown();
        this.recentRows = properties.dashboard().recentAuditRows();
    }

    public Snapshot snapshot() {
        Snapshot current = snapshot;
        if (current != null && isFresh(current.generatedAt(), statsRefresh)) {
            return current;
        }
        synchronized (snapshotLock) {
            current = snapshot;
            if (current == null || !isFresh(current.generatedAt(), statsRefresh)) {
                current = new Snapshot(clock.instant(), audit.stats(), audit.latest(recentRows),
                        rateLimiter.trackedClients());
                snapshot = current;
            }
            return current;
        }
    }

    /** @return the last verification result, or {@code null} if none was run yet */
    public IntegrityReport lastIntegrity() {
        return lastIntegrity;
    }

    /** Runs a full verification unless one ran less than {@code verifyCooldown} ago. */
    public VerifyResult verify() {
        synchronized (verifyLock) {
            IntegrityReport last = lastIntegrity;
            if (last != null && isFresh(last.verifiedAt(), verifyCooldown)) {
                Duration retryIn = Duration.between(clock.instant(), last.verifiedAt().plus(verifyCooldown));
                return new VerifyResult(last, false, retryIn);
            }
            IntegrityReport report = audit.verifyAll();
            lastIntegrity = report;
            return new VerifyResult(report, true, Duration.ZERO);
        }
    }

    private boolean isFresh(Instant at, Duration maxAge) {
        return at.plus(maxAge).isAfter(clock.instant());
    }
}
