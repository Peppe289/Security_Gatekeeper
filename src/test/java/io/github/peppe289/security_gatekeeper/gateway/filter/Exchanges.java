package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardResponse;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;

/** Test fixtures for the filter unit tests. */
final class Exchanges {

    static final String CLIENT_IP = "203.0.113.7";

    private Exchanges() {
    }

    static ProxyExchange get(String path) {
        return get(path, Map.of());
    }

    static ProxyExchange get(String path, Map<String, List<String>> headers) {
        return new ProxyExchange("GET", path, null, headers, new ByteArrayInputStream(new byte[0]), 0,
                CLIENT_IP, "http");
    }

    /** An exchange already resolved to {@code route}, as the filters after RouteResolutionFilter see it. */
    static ProxyExchange resolved(RoutePolicy route, Map<String, List<String>> headers) {
        ProxyExchange exchange = get("/" + route.getPrefix() + "/api", headers);
        exchange.resolveRoute(route.getPrefix(), route, "/api");
        return exchange;
    }

    /** What the rest of the chain returns when the request reaches the upstream. */
    static ProxyOutcome forwarded() {
        return new ProxyOutcome.Forwarded(new ForwardResponse(200, Map.of(), new ByteArrayInputStream(new byte[0])));
    }

    static RoutePolicy route(String prefix, boolean enabled, String apiKeyHash, long burst, long refill) {
        return new RoutePolicy(prefix, "http://upstream:8080", enabled, apiKeyHash, burst, refill);
    }

    static RoutePolicy publicRoute(String prefix) {
        return route(prefix, true, null, 10, 5);
    }
}
