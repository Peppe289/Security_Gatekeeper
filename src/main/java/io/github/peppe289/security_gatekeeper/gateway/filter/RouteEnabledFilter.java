package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.PolicyEvaluator;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** Feature toggle: a disabled route answers 503 without contacting the upstream. */
@Component
@Order(FilterOrder.ROUTE_ENABLED)
public class RouteEnabledFilter implements GatewayFilter {

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        AccessDecision decision = PolicyEvaluator.checkEnabled(exchange.route());
        return decision.isAllowed() ? chain.proceed(exchange) : ProxyOutcome.Rejected.of(decision);
    }
}
