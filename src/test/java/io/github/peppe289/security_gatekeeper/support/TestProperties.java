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
    public static final String HMAC_KEY = "test-hmac-key-of-at-least-32-characters!";

    public static final GatewayProperties.RateLimit RATE_LIMIT =
            new GatewayProperties.RateLimit(DEFAULT_BURST, DEFAULT_REFILL, 100_000, Duration.ofSeconds(60));
    public static final GatewayProperties.LoginThrottle LOGIN_THROTTLE =
            new GatewayProperties.LoginThrottle(5, Duration.ofSeconds(30));
    public static final GatewayProperties.Audit AUDIT = new GatewayProperties.Audit(50_000, 500,
            Duration.ofMillis(500), HMAC_KEY, List.of(), null, Duration.ofSeconds(60));

    private TestProperties() {
    }

    public static GatewayProperties defaults() {
        return withSeed(List.of());
    }

    public static GatewayProperties withSeed(List<GatewayProperties.SeedRoute> seed) {
        return build(seed, RATE_LIMIT, LOGIN_THROTTLE, AUDIT);
    }

    public static GatewayProperties with(GatewayProperties.RateLimit rateLimit) {
        return build(List.of(), rateLimit, LOGIN_THROTTLE, AUDIT);
    }

    public static GatewayProperties with(GatewayProperties.LoginThrottle loginThrottle) {
        return build(List.of(), RATE_LIMIT, loginThrottle, AUDIT);
    }

    public static GatewayProperties with(GatewayProperties.Audit audit) {
        return build(List.of(), RATE_LIMIT, LOGIN_THROTTLE, audit);
    }

    private static GatewayProperties build(List<GatewayProperties.SeedRoute> seed, GatewayProperties.RateLimit rateLimit,
                                           GatewayProperties.LoginThrottle loginThrottle,
                                           GatewayProperties.Audit audit) {
        return new GatewayProperties(
                "node-test",
                "X-Api-Key",
                new GatewayProperties.Admin("admin", null),
                new GatewayProperties.Forwarder(Duration.ofSeconds(5), Duration.ofSeconds(60)),
                new GatewayProperties.Routes(Duration.ofSeconds(10), seed),
                rateLimit,
                loginThrottle,
                audit,
                new GatewayProperties.Dashboard(STATS_REFRESH, VERIFY_COOLDOWN, RECENT_ROWS),
                new GatewayProperties.Monitoring(Duration.ofSeconds(5), Duration.ofMinutes(15)));
    }
}
