package io.github.peppe289.security_gatekeeper.gateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import io.github.peppe289.security_gatekeeper.route.RouteService;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RouteResolutionFilterTest {

    @Mock
    private RouteService routes;
    @Mock
    private GatewayFilterChain chain;

    private final ProxyOutcome downstream = Exchanges.forwarded();

    @InjectMocks
    private RouteResolutionFilter filter;

    @ParameterizedTest
    @CsvSource({
            "/svc/api/x,  /api/x",
            "/svc/,       /",
            "/svc,        ''",
            "/svc/a/b/c/, /a/b/c/"})
    void knownPrefixIsStrippedAndTheChainContinues(String path, String upstreamPath) {
        RoutePolicy route = Exchanges.publicRoute("svc");
        when(routes.find("svc")).thenReturn(Optional.of(route));
        ProxyExchange exchange = Exchanges.get(path);
        when(chain.proceed(exchange)).thenReturn(downstream);

        assertSame(downstream, filter.filter(exchange, chain));
        assertEquals("svc", exchange.routePrefix());
        assertSame(route, exchange.route());
        assertEquals(upstreamPath, exchange.upstreamPath());
    }

    @Test
    void unknownPrefixIsRejectedWith404AndRecordedForTheAudit() {
        when(routes.find("missing")).thenReturn(Optional.empty());
        ProxyExchange exchange = Exchanges.get("/missing/api");

        ProxyOutcome outcome = filter.filter(exchange, chain);

        assertEquals(AccessDecision.ROUTE_NOT_FOUND, outcome.decision());
        assertEquals(404, outcome.status());
        // The audit filter still sees which prefix was requested.
        assertEquals("missing", exchange.routePrefix());
        verify(chain, never()).proceed(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "", "/UPPER/x", "/-dash/x", "/with.dot/x", "/%2e%2e/etc"})
    void malformedPrefixIsRejectedWithoutLookingItUp(String path) {
        ProxyOutcome outcome = filter.filter(Exchanges.get(path), chain);

        assertEquals(AccessDecision.ROUTE_NOT_FOUND, outcome.decision());
        verifyNoInteractions(routes, chain);
    }
}
