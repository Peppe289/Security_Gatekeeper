package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Token bucket per (route, client IP). Runs after authentication checks so
 * that rejected requests do not consume the legitimate client's budget.
 */
@Component
@Order(FilterOrder.RATE_LIMIT)
public class RateLimitFilter implements GatewayFilter {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    private final RateLimiterService rateLimiter;

    public RateLimitFilter(RateLimiterService rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        RoutePolicy route = exchange.route();
        String key = RateLimiterService.routeKey(route.getPrefix(), exchange.clientIp());
        if (rateLimiter.tryAcquire(key, route.getBurstCapacity(), route.nanosPerToken())) {
            return chain.proceed(exchange);
        }
        long retryAfter = Math.max(1, (route.nanosPerToken() + NANOS_PER_SECOND - 1) / NANOS_PER_SECOND);
        return new ProxyOutcome.Rejected(AccessDecision.RATE_LIMITED, AccessDecision.RATE_LIMITED.httpStatus(), retryAfter);
    }
}
