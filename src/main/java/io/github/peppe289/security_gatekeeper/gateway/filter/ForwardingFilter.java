package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardingException;
import io.github.peppe289.security_gatekeeper.gateway.forward.HttpForwarder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** Terminal filter: sends the request upstream. Never calls the chain. */
@Component
@Order(FilterOrder.FORWARD)
public class ForwardingFilter implements GatewayFilter {

    private final HttpForwarder forwarder;

    public ForwardingFilter(HttpForwarder forwarder) {
        this.forwarder = forwarder;
    }

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        try {
            return new ProxyOutcome.Forwarded(forwarder.forward(exchange));
        } catch (ForwardingException e) {
            return new ProxyOutcome.Rejected(AccessDecision.FORWARD_FAILED, e.status(), 0);
        }
    }
}
