package io.github.peppe289.security_gatekeeper.gateway.pipeline;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Runs an exchange through all {@link GatewayFilter} beans, in
 * {@link org.springframework.core.annotation.Order} order.
 */
@Component
public class GatewayPipeline {

    private static final Logger log = LoggerFactory.getLogger(GatewayPipeline.class);

    private final List<GatewayFilter> filters;

    /** Spring injects the list already sorted by {@code @Order}. */
    public GatewayPipeline(List<GatewayFilter> filters) {
        this.filters = List.copyOf(filters);
        log.info("Gateway pipeline: {}", this.filters.stream().map(f -> f.getClass().getSimpleName()).toList());
    }

    public ProxyOutcome execute(ProxyExchange exchange) {
        return new GatewayFilterChain(filters).proceed(exchange);
    }
}
