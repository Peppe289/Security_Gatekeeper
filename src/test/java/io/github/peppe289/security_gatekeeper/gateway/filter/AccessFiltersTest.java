package io.github.peppe289.security_gatekeeper.gateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** The two access checks that need no collaborator other than the chain. */
@ExtendWith(MockitoExtension.class)
class AccessFiltersTest {

    private static final String KEY = "gk_secret-key";

    @Mock
    private GatewayFilterChain chain;

    private final ProxyOutcome downstream = Exchanges.forwarded();

    @Nested
    class RouteEnabled {

        private final RouteEnabledFilter filter = new RouteEnabledFilter();

        @Test
        void enabledRouteContinues() {
            ProxyExchange exchange = Exchanges.resolved(Exchanges.publicRoute("svc"), Map.of());
            when(chain.proceed(exchange)).thenReturn(downstream);

            assertSame(downstream, filter.filter(exchange, chain));
        }

        @Test
        void disabledRouteAnswers503WithoutForwarding() {
            RoutePolicy disabled = Exchanges.route("svc", false, null, 10, 5);

            ProxyOutcome outcome = filter.filter(Exchanges.resolved(disabled, Map.of()), chain);

            assertEquals(AccessDecision.ROUTE_DISABLED, outcome.decision());
            assertEquals(503, outcome.status());
            verifyNoInteractions(chain);
        }
    }

    @Nested
    class ApiKey {

        private final ApiKeyFilter filter = new ApiKeyFilter(TestProperties.defaults());
        private final RoutePolicy protectedRoute = Exchanges.route("svc", true, Sha256.hex(KEY), 10, 5);

        @Test
        void publicRouteNeedsNoKey() {
            ProxyExchange exchange = Exchanges.resolved(Exchanges.publicRoute("svc"), Map.of());
            when(chain.proceed(exchange)).thenReturn(downstream);

            assertSame(downstream, filter.filter(exchange, chain));
        }

        @Test
        void correctKeyContinuesWhateverTheHeaderCase() {
            ProxyExchange exchange = Exchanges.resolved(protectedRoute, Map.of("x-api-key", List.of(KEY)));
            when(chain.proceed(exchange)).thenReturn(downstream);

            assertSame(downstream, filter.filter(exchange, chain));
            verify(chain).proceed(exchange);
        }

        @Test
        void missingKeyAnswers401() {
            ProxyOutcome outcome = filter.filter(Exchanges.resolved(protectedRoute, Map.of()), chain);

            assertEquals(AccessDecision.API_KEY_MISSING, outcome.decision());
            assertEquals(401, outcome.status());
            verifyNoInteractions(chain);
        }

        @Test
        void wrongKeyAnswers403() {
            ProxyExchange exchange = Exchanges.resolved(protectedRoute, Map.of("X-Api-Key", List.of(KEY + "x")));

            ProxyOutcome outcome = filter.filter(exchange, chain);

            assertEquals(AccessDecision.API_KEY_INVALID, outcome.decision());
            assertEquals(403, outcome.status());
            verifyNoInteractions(chain);
        }
    }
}
