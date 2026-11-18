package io.github.peppe289.security_gatekeeper.core.ratelimit;

/**
 * Deterministic token-bucket rate limiter.
 *
 * <p>The bucket holds at most {@code capacity} tokens and gains one token every
 * {@code nanosPerToken} nanoseconds. Time is never read from the system clock:
 * every operation receives the current instant as a parameter, which keeps the
 * class fully deterministic (testable and amenable to OpenJML verification).
 *
 * <p>Timestamps are expressed on a <em>non-negative, monotonic</em> nanosecond
 * scale (e.g. {@code System.nanoTime() - origin}, computed by the caller).
 * Under this assumption every arithmetic operation in this class is free of
 * overflow, and no multiplication is needed: the refill uses only subtraction,
 * division and remainder.
 *
 * <p>Instances are <strong>not</strong> thread-safe; callers must synchronize
 * externally (the service layer keeps one bucket per client key).
 */
public final class TokenBucket {

    /** Maximum number of tokens the bucket can hold (burst size). */
    private final /*@ spec_public @*/ long capacity;

    /** Nanoseconds needed to generate a single token (inverse of the rate). */
    private final /*@ spec_public @*/ long nanosPerToken;

    /** Tokens currently stored, as of {@link #lastRefillNanos}. */
    private /*@ spec_public @*/ long tokens;

    /**
     * Instant up to which elapsed time has already been converted into tokens.
     * The fractional part of a period is carried over, so no time is lost.
     */
    private /*@ spec_public @*/ long lastRefillNanos;

    //@ public invariant capacity > 0;
    //@ public invariant nanosPerToken > 0;
    //@ public invariant 0 <= tokens && tokens <= capacity;
    //@ public invariant lastRefillNanos >= 0;

    /**
     * Creates a full bucket.
     *
     * @param capacity      maximum burst size, must be {@code > 0}
     * @param nanosPerToken refill period of one token, must be {@code > 0}
     * @param nowNanos      creation instant, must be {@code >= 0}
     * @throws IllegalArgumentException if any argument is out of range
     */
    /*@ public normal_behavior
      @   requires capacity > 0 && nanosPerToken > 0 && nowNanos >= 0;
      @   ensures this.capacity == capacity;
      @   ensures this.nanosPerToken == nanosPerToken;
      @   ensures this.tokens == capacity;
      @   ensures this.lastRefillNanos == nowNanos;
      @ also public exceptional_behavior
      @   requires capacity <= 0 || nanosPerToken <= 0 || nowNanos < 0;
      @   signals_only IllegalArgumentException;
      @*/
    public TokenBucket(long capacity, long nanosPerToken, long nowNanos) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be > 0");
        }
        if (nanosPerToken <= 0) {
            throw new IllegalArgumentException("nanosPerToken must be > 0");
        }
        if (nowNanos < 0) {
            throw new IllegalArgumentException("nowNanos must be >= 0");
        }
        this.capacity = capacity;
        this.nanosPerToken = nanosPerToken;
        this.tokens = capacity;
        this.lastRefillNanos = nowNanos;
    }

    /**
     * Number of tokens the bucket would hold at {@code nowNanos}, without
     * modifying its state.
     *
     * @param nowNanos current instant, must be {@code >= getLastRefillNanos()}
     * @return available tokens in {@code [getTokens(), getCapacity()]}
     * @throws IllegalArgumentException if the clock went backwards
     */
    /*@ public normal_behavior
      @   requires nowNanos >= lastRefillNanos;
      @   ensures tokens <= \result && \result <= capacity;
      @   ensures (nowNanos - lastRefillNanos) / nanosPerToken >= capacity - tokens
      @             ==> \result == capacity;
      @   ensures (nowNanos - lastRefillNanos) / nanosPerToken < capacity - tokens
      @             ==> \result == tokens + (nowNanos - lastRefillNanos) / nanosPerToken;
      @ also public exceptional_behavior
      @   requires nowNanos < lastRefillNanos;
      @   signals_only IllegalArgumentException;
      @ pure
      @*/
    public long availableTokens(long nowNanos) {
        requireMonotonic(nowNanos);
        long generated = (nowNanos - lastRefillNanos) / nanosPerToken;
        long missing = capacity - tokens;
        return tokens + Math.min(generated, missing);
    }

    /**
     * Shorthand for {@link #tryConsume(long, long) tryConsume(1, nowNanos)}.
     */
    /*@ public normal_behavior
      @   requires nowNanos >= lastRefillNanos;
      @   assignable tokens, lastRefillNanos;
      @   ensures \result <==> \old(availableTokens(nowNanos)) >= 1;
      @   ensures \result ==> tokens == \old(availableTokens(nowNanos)) - 1;
      @   ensures !\result ==> tokens == \old(availableTokens(nowNanos));
      @   ensures \old(lastRefillNanos) <= lastRefillNanos && lastRefillNanos <= nowNanos;
      @ also public exceptional_behavior
      @   requires nowNanos < lastRefillNanos;
      @   assignable \nothing;
      @   signals_only IllegalArgumentException;
      @*/
    public boolean tryConsume(long nowNanos) {
        return tryConsume(1, nowNanos);
    }

    /**
     * Refills the bucket up to {@code nowNanos}, then atomically consumes
     * {@code permits} tokens if enough are available. On rejection no token is
     * consumed (all-or-nothing).
     *
     * @param permits  tokens requested, must be {@code > 0}
     * @param nowNanos current instant, must be {@code >= getLastRefillNanos()}
     * @return {@code true} if the request is allowed
     * @throws IllegalArgumentException if {@code permits <= 0} or the clock went backwards
     */
    /*@ public normal_behavior
      @   requires permits > 0;
      @   requires nowNanos >= lastRefillNanos;
      @   assignable tokens, lastRefillNanos;
      @   ensures \result <==> \old(availableTokens(nowNanos)) >= permits;
      @   ensures \result ==> tokens == \old(availableTokens(nowNanos)) - permits;
      @   ensures !\result ==> tokens == \old(availableTokens(nowNanos));
      @   ensures \old(lastRefillNanos) <= lastRefillNanos && lastRefillNanos <= nowNanos;
      @ also public exceptional_behavior
      @   requires permits <= 0 || nowNanos < lastRefillNanos;
      @   assignable \nothing;
      @   signals_only IllegalArgumentException;
      @*/
    public boolean tryConsume(long permits, long nowNanos) {
        if (permits <= 0) {
            throw new IllegalArgumentException("permits must be > 0");
        }
        refill(nowNanos);
        if (tokens >= permits) {
            tokens = tokens - permits;
            return true;
        }
        return false;
    }

    /**
     * Converts the time elapsed since {@link #lastRefillNanos} into tokens.
     * <ul>
     *   <li>If the bucket becomes full, any excess time is discarded
     *       ({@code lastRefillNanos = nowNanos}): idle time cannot be banked.</li>
     *   <li>Otherwise the remainder of an incomplete period is preserved by
     *       moving {@code lastRefillNanos} back by {@code elapsed % nanosPerToken}.</li>
     * </ul>
     */
    /*@ private normal_behavior
      @   requires nowNanos >= lastRefillNanos;
      @   assignable tokens, lastRefillNanos;
      @   ensures tokens == \old(availableTokens(nowNanos));
      @   ensures tokens == capacity ==> lastRefillNanos == nowNanos;
      @   ensures tokens < capacity
      @             ==> lastRefillNanos == nowNanos - (nowNanos - \old(lastRefillNanos)) % nanosPerToken;
      @ also private exceptional_behavior
      @   requires nowNanos < lastRefillNanos;
      @   assignable \nothing;
      @   signals_only IllegalArgumentException;
      @*/
    private void refill(long nowNanos) {
        long available = availableTokens(nowNanos);
        if (available == capacity) {
            lastRefillNanos = nowNanos;
        } else {
            long elapsed = nowNanos - lastRefillNanos;
            lastRefillNanos = nowNanos - elapsed % nanosPerToken;
        }
        tokens = available;
    }

    /*@ private normal_behavior
      @   requires nowNanos >= lastRefillNanos;
      @ also private exceptional_behavior
      @   requires nowNanos < lastRefillNanos;
      @   signals_only IllegalArgumentException;
      @ pure
      @*/
    private void requireMonotonic(long nowNanos) {
        if (nowNanos < lastRefillNanos) {
            throw new IllegalArgumentException("clock went backwards");
        }
    }

    /** @return the maximum burst size */
    /*@ public normal_behavior
      @   ensures \result == capacity;
      @*/
    public /*@ pure @*/ long getCapacity() {
        return capacity;
    }

    /** @return nanoseconds needed to generate one token */
    /*@ public normal_behavior
      @   ensures \result == nanosPerToken;
      @*/
    public /*@ pure @*/ long getNanosPerToken() {
        return nanosPerToken;
    }

    /** @return tokens stored as of the last refill (no refill is performed) */
    /*@ public normal_behavior
      @   ensures \result == tokens;
      @*/
    public /*@ pure @*/ long getTokens() {
        return tokens;
    }

    /** @return the instant up to which time has been converted into tokens */
    /*@ public normal_behavior
      @   ensures \result == lastRefillNanos;
      @*/
    public /*@ pure @*/ long getLastRefillNanos() {
        return lastRefillNanos;
    }
}
