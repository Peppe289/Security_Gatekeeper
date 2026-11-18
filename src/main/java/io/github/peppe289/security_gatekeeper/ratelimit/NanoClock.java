package io.github.peppe289.security_gatekeeper.ratelimit;

/**
 * Monotonic, non-negative nanosecond clock. Abstracted so rate limiting can be
 * tested deterministically (the core {@code TokenBucket} never reads time itself).
 */
@FunctionalInterface
public interface NanoClock {

    long nanos();

    /** A clock starting at 0 when created, backed by {@link System#nanoTime()}. */
    static NanoClock system() {
        long origin = System.nanoTime();
        return () -> Math.max(0L, System.nanoTime() - origin);
    }
}
