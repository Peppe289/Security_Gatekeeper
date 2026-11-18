package io.github.peppe289.security_gatekeeper.gateway.filter;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.PolicyEvaluator;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.FilterOrder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import io.github.peppe289.security_gatekeeper.route.RouteService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Maps {@code /{prefix}/rest} to a route: the first path segment selects the
 * route and the remainder ({@code /rest}) is what the upstream receives.
 * E.g. {@code /myservice/api/x} with {@code myservice -> http://localhost:8080}
 * becomes {@code http://localhost:8080/api/x}.
 */
@Component
@Order(FilterOrder.ROUTE_RESOLUTION)
public class RouteResolutionFilter implements GatewayFilter {

    private final RouteService routes;

    public RouteResolutionFilter(RouteService routes) {
        this.routes = routes;
    }

    @Override
    public ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain) {
        String path = exchange.path();
        int start = path.startsWith("/") ? 1 : 0;
        int slash = path.indexOf('/', start);
        String prefix = slash < 0 ? path.substring(start) : path.substring(start, slash);
        String rest = slash < 0 ? "" : path.substring(slash);

        if (!RoutePolicy.isValidPrefix(prefix)) {
            return ProxyOutcome.Rejected.of(AccessDecision.ROUTE_NOT_FOUND);
        }
        RoutePolicy route = routes.find(prefix).orElse(null);
        exchange.resolveRoute(prefix, route, rest);
        AccessDecision decision = PolicyEvaluator.checkExists(route);
        return decision.isAllowed() ? chain.proceed(exchange) : ProxyOutcome.Rejected.of(decision);
    }
}
