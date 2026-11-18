package io.github.peppe289.security_gatekeeper.gateway.pipeline;

import java.util.List;

/**
 * Cursor over the ordered filters for a single request. Not shared between
 * requests: {@link GatewayPipeline} creates one per exchange.
 */
public final class GatewayFilterChain {

    private final List<GatewayFilter> filters;
    private int position;

    GatewayFilterChain(List<GatewayFilter> filters) {
        this.filters = filters;
    }

    /** Invokes the next filter. */
    public ProxyOutcome proceed(ProxyExchange exchange) {
        if (position >= filters.size()) {
            throw new IllegalStateException("Gateway pipeline ended without a terminal filter");
        }
        return filters.get(position++).filter(exchange, this);
    }
}
