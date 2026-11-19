package io.github.peppe289.security_gatekeeper.support;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import java.time.Duration;
import java.util.List;

/** {@link GatewayProperties} for unit tests, built without Spring: the defaults of {@code application.yml}. */
public final class TestProperties {

    public static final long DEFAULT_BURST = 100;
    public static final long DEFAULT_REFILL = 50;
    public static final Duration STATS_REFRESH = Duration.ofSeconds(5);
    public static final Duration VERIFY_COOLDOWN = Duration.ofSeconds(30);
    public static final int RECENT_ROWS = 50;

    private TestProperties() {
    }

    public static GatewayProperties defaults() {
        return withSeed(List.of());
    }

    public static GatewayProperties withSeed(List<GatewayProperties.SeedRoute> seed) {
        return new GatewayProperties(
                "node-test",
                "X-Api-Key",
                new GatewayProperties.Admin("admin", null),
                new GatewayProperties.Forwarder(Duration.ofSeconds(5), Duration.ofSeconds(60)),
                new GatewayProperties.Routes(Duration.ofSeconds(10), seed),
                new GatewayProperties.RateLimit(DEFAULT_BURST, DEFAULT_REFILL, 100_000, Duration.ofSeconds(60)),
                new GatewayProperties.LoginThrottle(5, Duration.ofSeconds(30)),
                new GatewayProperties.Audit(50_000, 500, Duration.ofMillis(500),
                        "test-hmac-key-of-at-least-32-characters!", List.of(), null, Duration.ofSeconds(60)),
                new GatewayProperties.Dashboard(STATS_REFRESH, VERIFY_COOLDOWN, RECENT_ROWS),
                new GatewayProperties.Monitoring(Duration.ofSeconds(5), Duration.ofMinutes(15)));
    }
}
