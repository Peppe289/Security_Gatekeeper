package io.github.peppe289.security_gatekeeper.gateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock
    private RateLimiterService rateLimiter;
    @Mock
    private GatewayFilterChain chain;

    private final ProxyOutcome downstream = Exchanges.forwarded();

    @InjectMocks
    private RateLimitFilter filter;

    @Test
    void bucketIsKeyedByRouteAndClientAndSizedByTheRoute() {
        RoutePolicy route = Exchanges.route("svc", true, null, 20, 4);
        ProxyExchange exchange = Exchanges.resolved(route, Map.of());
        when(rateLimiter.tryAcquire(anyString(), anyLong(), anyLong())).thenReturn(true);
        when(chain.proceed(exchange)).thenReturn(downstream);

        assertSame(downstream, filter.filter(exchange, chain));
        verify(rateLimiter).tryAcquire(RateLimiterService.routeKey("svc", Exchanges.CLIENT_IP), 20, 250_000_000L);
    }

    @Test
    void exhaustedBucketAnswers429WithRetryAfter() {
        ProxyExchange exchange = Exchanges.resolved(Exchanges.route("svc", true, null, 20, 4), Map.of());
        when(rateLimiter.tryAcquire(anyString(), anyLong(), anyLong())).thenReturn(false);

        ProxyOutcome outcome = filter.filter(exchange, chain);

        ProxyOutcome.Rejected rejected = assertInstanceOf(ProxyOutcome.Rejected.class, outcome);
        assertEquals(AccessDecision.RATE_LIMITED, rejected.decision());
        assertEquals(429, rejected.status());
        assertEquals(1, rejected.retryAfterSeconds());
        verifyNoInteractions(chain);
    }

    @Test
    void retryAfterIsTheTimeToTheNextTokenRoundedUp() {
        // One token per second at the slowest refill rate: never answer "retry after 0 s".
        ProxyExchange exchange = Exchanges.resolved(Exchanges.route("svc", true, null, 1, 1), Map.of());
        when(rateLimiter.tryAcquire(anyString(), anyLong(), anyLong())).thenReturn(false);

        ProxyOutcome.Rejected rejected = (ProxyOutcome.Rejected) filter.filter(exchange, chain);

        assertEquals(1, rejected.retryAfterSeconds());
    }
}
