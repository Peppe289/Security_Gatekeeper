package io.github.peppe289.security_gatekeeper.ratelimit;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.ratelimit.TokenBucket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Thread-safe registry of {@link TokenBucket}s keyed by an arbitrary string
 * (route + client IP, or login + client IP).
 *
 * <p>Memory is bounded: idle (full) buckets are evicted periodically and, if
 * {@code maxTrackedClients} is still reached, new clients are rejected
 * (fail-closed) instead of letting the map grow without limit.
 */
@Service
public class RateLimiterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterService.class);

    private static final long INLINE_EVICTION_INTERVAL_NANOS = 1_000_000_000L;

    private final ConcurrentMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final AtomicLong nextInlineEvictionNanos = new AtomicLong();
    private final NanoClock clock;
    private final int maxTrackedClients;

    public RateLimiterService(NanoClock clock, GatewayProperties properties) {
        this.clock = clock;
        this.maxTrackedClients = properties.rateLimit().maxTrackedClients();
    }

    public static String routeKey(String prefix, String clientId) {
        return routeKeyPrefix(prefix) + clientId;
    }

    public static String routeKeyPrefix(String prefix) {
        return "route:" + prefix + "|";
    }

    /**
     * Consumes one token from the bucket identified by {@code key}, creating a
     * full bucket with the given parameters on first use.
     *
     * @return {@code true} if the request may proceed
     */
    public boolean tryAcquire(String key, long capacity, long nanosPerToken) {
        TokenBucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= maxTrackedClients) {
                boolean evicted = evictIdleThrottled();
                if (buckets.size() >= maxTrackedClients) {
                    if (evicted) {
                        log.warn("Rate limiter tracks {} clients (limit reached): rejecting new clients",
                                buckets.size());
                    }
                    return false;
                }
            }
            bucket = buckets.computeIfAbsent(key, k -> new TokenBucket(capacity, nanosPerToken, clock.nanos()));
        }
        synchronized (bucket) {
            return bucket.tryConsume(now(bucket));
        }
    }

    /** @return {@code true} if a bucket exists for {@code key} and holds no token right now */
    public boolean isExhausted(String key) {
        TokenBucket bucket = buckets.get(key);
        if (bucket == null) {
            return false;
        }
        synchronized (bucket) {
            return bucket.availableTokens(now(bucket)) == 0;
        }
    }

    public void reset(String key) {
        buckets.remove(key);
    }

    /** Drops every bucket whose key starts with {@code keyPrefix} (e.g. after a route is deleted). */
    public void resetAll(String keyPrefix) {
        buckets.keySet().removeIf(k -> k.startsWith(keyPrefix));
    }

    /**
     * Removes buckets that are full again: forgetting them is equivalent to
     * keeping them, since a new bucket also starts full.
     */
    public void evictIdle() {
        for (Map.Entry<String, TokenBucket> e : buckets.entrySet()) {
            TokenBucket bucket = e.getValue();
            synchronized (bucket) {
                if (bucket.availableTokens(now(bucket)) == bucket.getCapacity()) {
                    buckets.remove(e.getKey(), bucket);
                }
            }
        }
    }

    /**
     * Full scans are O(n) under per-bucket locks: when the registry is full, a flood of new
     * clients must not trigger one per request. Runs {@link #evictIdle()} at most once per
     * {@link #INLINE_EVICTION_INTERVAL_NANOS}.
     *
     * @return {@code true} if this call ran the eviction
     */
    private boolean evictIdleThrottled() {
        long now = clock.nanos();
        long next = nextInlineEvictionNanos.get();
        if (now < next || !nextInlineEvictionNanos.compareAndSet(next, now + INLINE_EVICTION_INTERVAL_NANOS)) {
            return false;
        }
        evictIdle();
        return true;
    }

    public int trackedClients() {
        return buckets.size();
    }

    /** Guards against a clock read on another thread being slightly behind the bucket's last refill. */
    private long now(TokenBucket bucket) {
        return Math.max(clock.nanos(), bucket.getLastRefillNanos());
    }
}
