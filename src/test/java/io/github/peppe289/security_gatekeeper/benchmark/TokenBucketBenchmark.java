package io.github.peppe289.security_gatekeeper.benchmark;

import io.github.peppe289.security_gatekeeper.core.ratelimit.TokenBucket;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Latency of a single rate-limit decision.
 * Run with: {@code mvn -Pbenchmark -DskipTests verify}
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Thread)
public class TokenBucketBenchmark {

    private TokenBucket bucket;
    private long now;

    @Setup(Level.Iteration)
    public void setUp() {
        now = 0;
        bucket = new TokenBucket(1_000, 1_000, now);
    }

    /** Typical path: clock advances a bit, refill + consume. */
    @Benchmark
    public boolean tryConsumeAdvancingClock() {
        now += 500;
        return bucket.tryConsume(now);
    }

    /** Bucket mostly empty: measures the rejection path. */
    @Benchmark
    public boolean tryConsumeSaturated() {
        now += 1;
        return bucket.tryConsume(now);
    }

    /** Read-only query used e.g. for X-RateLimit-Remaining headers. */
    @Benchmark
    public long availableTokens() {
        now += 500;
        return bucket.availableTokens(now);
    }
}
