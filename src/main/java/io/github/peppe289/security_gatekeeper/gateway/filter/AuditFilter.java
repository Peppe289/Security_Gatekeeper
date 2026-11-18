package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Outermost filter: records the final outcome of every request (allowed,
 * rejected or failed). The query string is never recorded, as it may carry
 * secrets.
 */
@Component
@Order(FilterOrder.AUDIT)
public class AuditFilter implements GatewayFilter {

    private final AuditService audit;

    public AuditFilter(AuditService audit) {
        this.audit = audit;
    }

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        ProxyOutcome outcome;
        try {
            outcome = chain.proceed(exchange);
        } catch (RuntimeException e) {
            audit.record(exchange.clientIp(), exchange.method(), exchange.path(), exchange.routePrefix(),
                    AccessDecision.FORWARD_FAILED, 500);
            throw e;
        }
        audit.record(exchange.clientIp(), exchange.method(), exchange.path(), exchange.routePrefix(),
                outcome.decision(), outcome.status());
        return outcome;
    }
}
