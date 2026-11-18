package io.github.peppe289.security_gatekeeper.route;

/**
 * Request to create a route. {@code null} rate parameters fall back to the
 * configured defaults.
 */
public record RouteDefinition(
        String prefix,
        String targetUrl,
        boolean enabled,
        boolean requireApiKey,
        Long burstCapacity,
        Long refillPerSecond) {
}
