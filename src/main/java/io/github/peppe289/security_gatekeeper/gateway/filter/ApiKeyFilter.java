package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.PolicyEvaluator;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Optional per-route protection: when a route has an API key, clients must
 * send it in the configured header (default {@code X-Api-Key}). Useful to
 * expose an internal service that has no authentication of its own only to
 * known clients. The header is stripped before forwarding.
 */
@Component
@Order(FilterOrder.API_KEY)
public class ApiKeyFilter implements GatewayFilter {

    private final String header;

    public ApiKeyFilter(GatewayProperties properties) {
        this.header = properties.apiKeyHeader();
    }

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        AccessDecision decision = PolicyEvaluator.checkApiKey(exchange.route(), exchange.header(header));
        return decision.isAllowed() ? chain.proceed(exchange) : ProxyOutcome.Rejected.of(decision);
    }
}
