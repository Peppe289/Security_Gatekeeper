package io.github.peppe289.security_gatekeeper.ratelimit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Registry of token buckets, driven by a fake clock so every test is deterministic.
 * Buckets used here hold {@value #CAPACITY} tokens and gain one every {@value #PERIOD} ns.
 */
class RateLimiterServiceTest {

    private static final long CAPACITY = 2;
    private static final long PERIOD = 100_000_000L; // 100 ms per token
    private static final long ONE_SECOND = 1_000_000_000L;

    private final AtomicLong now = new AtomicLong();
    private final NanoClock clock = now::get;

    private RateLimiterService limiter(int maxTrackedClients) {
        GatewayProperties properties = TestProperties.with(new GatewayProperties.RateLimit(
                TestProperties.DEFAULT_BURST, TestProperties.DEFAULT_REFILL, maxTrackedClients, Duration.ofSeconds(60)));
        return new RateLimiterService(clock, properties);
    }

    private static boolean acquire(RateLimiterService limiter, String key) {
        return limiter.tryAcquire(key, CAPACITY, PERIOD);
    }

    @Test
    void routeKeysAreScopedByRoute() {
        assertEquals("route:svc|10.0.0.1", RateLimiterService.routeKey("svc", "10.0.0.1"));
        assertTrue(RateLimiterService.routeKey("svc", "x").startsWith(RateLimiterService.routeKeyPrefix("svc")));
    }

    @Nested
    class Acquire {

        private RateLimiterService limiter;

        @BeforeEach
        void setUp() {
            limiter = limiter(100);
        }

        @Test
        void newClientStartsWithAFullBurst() {
            assertTrue(acquire(limiter, "a"));
            assertTrue(acquire(limiter, "a"));
            assertFalse(acquire(limiter, "a"));
        }

        @Test
        void tokensComeBackOverTime() {
            acquire(limiter, "a");
            acquire(limiter, "a");

            now.addAndGet(PERIOD - 1);
            assertFalse(acquire(limiter, "a"));
            now.addAndGet(1);
            assertTrue(acquire(limiter, "a"));
        }

        @Test
        void clientsHaveSeparateBuckets() {
            acquire(limiter, "a");
            acquire(limiter, "a");

            assertFalse(acquire(limiter, "a"));
            assertTrue(acquire(limiter, "b"));
            assertEquals(2, limiter.trackedClients());
        }
    }

    @Nested
    class Exhaustion {

        private final RateLimiterService limiter = limiter(100);

        @Test
        void unknownKeyIsNotExhausted() {
            assertFalse(limiter.isExhausted("a"));
        }

        @Test
        void bucketWithTokensLeftIsNotExhausted() {
            acquire(limiter, "a");
            assertFalse(limiter.isExhausted("a"));
        }

        @Test
        void emptyBucketIsExhaustedUntilItRefills() {
            acquire(limiter, "a");
            acquire(limiter, "a");
            assertTrue(limiter.isExhausted("a"));

            now.addAndGet(PERIOD);
            assertFalse(limiter.isExhausted("a"));
        }
    }

    @Nested
    class Reset {

        private final RateLimiterService limiter = limiter(100);

        @Test
        void resetGivesTheClientAFullBucketAgain() {
            acquire(limiter, "a");
            acquire(limiter, "a");

            limiter.reset("a");

            assertEquals(0, limiter.trackedClients());
            assertTrue(acquire(limiter, "a"));
        }

        @Test
        void resetAllRemovesOnlyTheKeysWithThePrefix() {
            String svc1 = RateLimiterService.routeKey("svc", "1");
            String svc2 = RateLimiterService.routeKey("svc", "2");
            String other = RateLimiterService.routeKey("svc2", "1");
            acquire(limiter, svc1);
            acquire(limiter, svc2);
            acquire(limiter, other);

            limiter.resetAll(RateLimiterService.routeKeyPrefix("svc"));

            assertEquals(1, limiter.trackedClients());
        }
    }

    @Nested
    class Eviction {

        private final RateLimiterService limiter = limiter(100);

        @Test
        void fullBucketsAreForgottenAndPartialOnesKept() {
            acquire(limiter, "idle");
            acquire(limiter, "busy");
            acquire(limiter, "busy");
            now.addAndGet(PERIOD); // "idle" is full again, "busy" holds one token of two

            limiter.evictIdle();

            assertEquals(1, limiter.trackedClients());
            // "busy" kept its state: one token left, not a fresh full bucket
            assertTrue(acquire(limiter, "busy"));
            assertFalse(acquire(limiter, "busy"));
        }
    }

    /** Memory bound: at {@code maxTrackedClients} new clients are refused, existing ones are not. */
    @Nested
    class Capacity {

        @Test
        void belowTheLimitNewClientsAreAccepted() {
            RateLimiterService limiter = limiter(2);
            assertTrue(acquire(limiter, "a"));
            assertTrue(acquire(limiter, "b"));
            assertEquals(2, limiter.trackedClients());
        }

        @Test
        void atTheLimitNewClientsAreRejectedButKnownOnesServed() {
            RateLimiterService limiter = limiter(1);
            acquire(limiter, "a"); // not full: cannot be evicted

            assertFalse(acquire(limiter, "b"), "fail-closed when the registry is full");
            assertTrue(acquire(limiter, "a"));
            assertEquals(1, limiter.trackedClients());
        }

        @Test
        void idleClientsAreEvictedToMakeRoom() {
            RateLimiterService limiter = limiter(1);
            acquire(limiter, "a");
            now.addAndGet(PERIOD); // "a" is full again

            assertTrue(acquire(limiter, "b"));
            assertEquals(1, limiter.trackedClients());
        }

        @Test
        void inlineEvictionRunsAtMostOncePerSecond() {
            RateLimiterService limiter = limiter(1);
            acquire(limiter, "a");
            acquire(limiter, "a"); // "a" empty

            assertFalse(acquire(limiter, "b")); // eviction runs, nothing to evict

            now.addAndGet(ONE_SECOND / 2); // "a" is full again, but the last scan was 0.5 s ago
            assertFalse(acquire(limiter, "b"));

            now.addAndGet(ONE_SECOND / 2); // one second after the first scan
            assertTrue(acquire(limiter, "b"));
        }
    }
}
