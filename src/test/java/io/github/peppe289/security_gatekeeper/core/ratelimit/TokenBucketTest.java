package io.github.peppe289.security_gatekeeper.core.ratelimit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests are written against exact boundaries (x-1, x, x+1) so that PiTest's
 * conditional-boundary, negation, math and return-value mutators are all killed.
 */
class TokenBucketTest {

    private static final long PERIOD = 100L; // ns per token
    private static final long CAP = 5L;
    /** Deliberately not a multiple of PERIOD, so (now - t0) % P != (now + t0) % P. */
    private static final long T0 = 1_037L;

    private static TokenBucket bucket() {
        return new TokenBucket(CAP, PERIOD, T0);
    }

    /** Drains the bucket at instant {@code t} and checks it is empty. */
    private static void drain(TokenBucket b, long t) {
        assertTrue(b.tryConsume(b.availableTokens(t), t));
        assertEquals(0, b.getTokens());
    }

    @Nested
    @DisplayName("constructor")
    class Constructor {

        @Test
        void startsFullWithGivenParameters() {
            TokenBucket b = bucket();
            assertEquals(CAP, b.getCapacity());
            assertEquals(PERIOD, b.getNanosPerToken());
            assertEquals(CAP, b.getTokens());
            assertEquals(T0, b.getLastRefillNanos());
        }

        @Test
        void acceptsSmallestLegalValues() {
            TokenBucket b = new TokenBucket(1, 1, 0);
            assertEquals(1, b.getCapacity());
            assertEquals(1, b.getNanosPerToken());
            assertEquals(1, b.getTokens());
            assertEquals(0, b.getLastRefillNanos());
        }

        @ParameterizedTest
        @ValueSource(longs = {0L, -1L, Long.MIN_VALUE})
        void rejectsNonPositiveCapacity(long capacity) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new TokenBucket(capacity, PERIOD, T0));
            assertEquals("capacity must be > 0", e.getMessage());
        }

        @ParameterizedTest
        @ValueSource(longs = {0L, -1L, Long.MIN_VALUE})
        void rejectsNonPositivePeriod(long period) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new TokenBucket(CAP, period, T0));
            assertEquals("nanosPerToken must be > 0", e.getMessage());
        }

        @ParameterizedTest
        @ValueSource(longs = {-1L, Long.MIN_VALUE})
        void rejectsNegativeStartInstant(long now) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new TokenBucket(CAP, PERIOD, now));
            assertEquals("nowNanos must be >= 0", e.getMessage());
        }
    }

    @Nested
    @DisplayName("tryConsume")
    class TryConsume {

        @Test
        void singlePermitDecrementsByOne() {
            TokenBucket b = bucket();
            assertTrue(b.tryConsume(T0));
            assertEquals(CAP - 1, b.getTokens());
        }

        @Test
        void consumingExactlyAllTokensIsAllowed() {
            TokenBucket b = bucket();
            assertTrue(b.tryConsume(CAP, T0));
            assertEquals(0, b.getTokens());
        }

        @Test
        void requestingOneMoreThanAvailableIsRejectedAndConsumesNothing() {
            TokenBucket b = bucket();
            assertFalse(b.tryConsume(CAP + 1, T0));
            assertEquals(CAP, b.getTokens());
        }

        @Test
        void emptyBucketRejectsUntilAFullPeriodElapses() {
            TokenBucket b = bucket();
            drain(b, T0);
            assertFalse(b.tryConsume(T0 + PERIOD - 1));
            assertEquals(0, b.getTokens());
            assertTrue(b.tryConsume(T0 + PERIOD));
            assertEquals(0, b.getTokens());
            assertFalse(b.tryConsume(T0 + PERIOD));
        }

        @Test
        void exhaustsAfterCapacityRequestsAtSameInstant() {
            TokenBucket b = bucket();
            for (int i = 0; i < CAP; i++) {
                assertTrue(b.tryConsume(T0), "request " + i);
            }
            assertFalse(b.tryConsume(T0));
        }

        @ParameterizedTest
        @ValueSource(longs = {0L, -1L, Long.MIN_VALUE})
        void rejectsNonPositivePermitsWithoutSideEffects(long permits) {
            TokenBucket b = bucket();
            drain(b, T0);
            long later = T0 + 3 * PERIOD;
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> b.tryConsume(permits, later));
            assertEquals("permits must be > 0", e.getMessage());
            assertEquals(0, b.getTokens());
            assertEquals(T0, b.getLastRefillNanos());
        }

        @Test
        void rejectsClockGoingBackwardsWithoutSideEffects() {
            TokenBucket b = bucket();
            assertTrue(b.tryConsume(T0));
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> b.tryConsume(T0 - 1));
            assertEquals("clock went backwards", e.getMessage());
            assertEquals(CAP - 1, b.getTokens());
            assertEquals(T0, b.getLastRefillNanos());
        }
    }

    @Nested
    @DisplayName("refill")
    class Refill {

        @Test
        void partialRefillAddsOneTokenPerElapsedPeriod() {
            TokenBucket b = bucket();
            drain(b, T0);
            assertTrue(b.tryConsume(1, T0 + 3 * PERIOD));
            assertEquals(2, b.getTokens());
            assertEquals(T0 + 3 * PERIOD, b.getLastRefillNanos());
        }

        @Test
        void fractionalPeriodIsCarriedOverNotLost() {
            TokenBucket b = bucket();
            drain(b, T0);
            long t = T0 + PERIOD + PERIOD / 2;          // 1.5 periods
            assertTrue(b.tryConsume(t));                // the one generated token
            assertEquals(T0 + PERIOD, b.getLastRefillNanos());
            // Next token due at T0 + 2*PERIOD, i.e. only half a period after t.
            assertFalse(b.tryConsume(T0 + 2 * PERIOD - 1));
            assertTrue(b.tryConsume(T0 + 2 * PERIOD));
        }

        @Test
        void refillReachingCapacityExactlyFillsBucketAndResetsClock() {
            TokenBucket b = bucket();
            drain(b, T0);
            long t = T0 + CAP * PERIOD + PERIOD / 2;    // exactly CAP tokens generated
            assertEquals(CAP, b.availableTokens(t));
            assertTrue(b.tryConsume(1, t));
            assertEquals(CAP - 1, b.getTokens());
            assertEquals(t, b.getLastRefillNanos());    // excess half period discarded
        }

        @Test
        void refillOneShortOfCapacityKeepsRemainder() {
            TokenBucket b = bucket();
            drain(b, T0);
            long t = T0 + (CAP - 1) * PERIOD + PERIOD / 2;
            assertEquals(CAP - 1, b.availableTokens(t));
            assertTrue(b.tryConsume(1, t));
            assertEquals(CAP - 2, b.getTokens());
            assertEquals(T0 + (CAP - 1) * PERIOD, b.getLastRefillNanos());
        }

        @Test
        void idleTimeOnFullBucketCannotBeBanked() {
            TokenBucket b = bucket();
            long t = T0 + 1_000 * PERIOD + PERIOD - 1;  // long idle, almost one more period
            drain(b, t);
            assertEquals(t, b.getLastRefillNanos());
            assertFalse(b.tryConsume(t + 1));           // no hidden credit from the idle tail
            assertTrue(b.tryConsume(t + PERIOD));
        }

        @Test
        void rejectedRequestStillPersistsRefill() {
            TokenBucket b = bucket();
            drain(b, T0);
            long t = T0 + 2 * PERIOD;
            assertFalse(b.tryConsume(3, t));
            assertEquals(2, b.getTokens());
            assertEquals(t, b.getLastRefillNanos());
        }

        @Test
        void hugeElapsedTimeDoesNotOverflow() {
            TokenBucket b = new TokenBucket(Long.MAX_VALUE, 1, 0);
            assertTrue(b.tryConsume(Long.MAX_VALUE, 0));
            assertEquals(Long.MAX_VALUE, b.availableTokens(Long.MAX_VALUE));
            assertTrue(b.tryConsume(Long.MAX_VALUE, Long.MAX_VALUE));
            assertEquals(0, b.getTokens());
            assertEquals(Long.MAX_VALUE, b.getLastRefillNanos());
        }
    }

    @Nested
    @DisplayName("availableTokens")
    class AvailableTokens {

        @Test
        void isPureAndDoesNotMutateState() {
            TokenBucket b = bucket();
            drain(b, T0);
            assertEquals(3, b.availableTokens(T0 + 3 * PERIOD));
            assertEquals(0, b.getTokens());
            assertEquals(T0, b.getLastRefillNanos());
        }

        @Test
        void boundaryAroundOnePeriod() {
            TokenBucket b = bucket();
            drain(b, T0);
            assertEquals(0, b.availableTokens(T0));
            assertEquals(0, b.availableTokens(T0 + PERIOD - 1));
            assertEquals(1, b.availableTokens(T0 + PERIOD));
            assertEquals(1, b.availableTokens(T0 + PERIOD + 1));
        }

        @Test
        void isCappedAtCapacity() {
            TokenBucket b = bucket();
            assertTrue(b.tryConsume(2, T0));
            assertEquals(CAP - 1, b.availableTokens(T0 + PERIOD));
            assertEquals(CAP, b.availableTokens(T0 + 2 * PERIOD));
            assertEquals(CAP, b.availableTokens(T0 + 3 * PERIOD));
        }

        @Test
        void rejectsClockGoingBackwards() {
            TokenBucket b = bucket();
            assertThrows(IllegalArgumentException.class, () -> b.availableTokens(T0 - 1));
            assertEquals(CAP, b.availableTokens(T0));
        }
    }
}
