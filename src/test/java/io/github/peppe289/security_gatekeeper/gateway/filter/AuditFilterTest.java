package io.github.peppe289.security_gatekeeper.gateway.filter;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import java.io.ByteArrayInputStream;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuditFilterTest {

    @Mock
    private AuditService audit;
    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private AuditFilter filter;

    @Test
    void recordsTheFinalOutcomeOnceAndReturnsIt() {
        ProxyExchange exchange = Exchanges.resolved(Exchanges.publicRoute("svc"), Map.of());
        ProxyOutcome rejected = ProxyOutcome.Rejected.of(AccessDecision.RATE_LIMITED);
        when(chain.proceed(exchange)).thenReturn(rejected);

        assertSame(rejected, filter.filter(exchange, chain));

        verify(audit).record(Exchanges.CLIENT_IP, "GET", "/svc/api", "svc", AccessDecision.RATE_LIMITED, 429);
        verifyNoMoreInteractions(audit);
    }

    @Test
    void neverRecordsTheQueryString() {
        ProxyExchange exchange = new ProxyExchange("POST", "/svc/login", "token=secret", Map.of(),
                new ByteArrayInputStream(new byte[0]), 0, Exchanges.CLIENT_IP, "https");
        when(chain.proceed(exchange)).thenReturn(ProxyOutcome.Rejected.of(AccessDecision.ROUTE_NOT_FOUND));

        filter.filter(exchange, chain);

        verify(audit).record(Exchanges.CLIENT_IP, "POST", "/svc/login", "", AccessDecision.ROUTE_NOT_FOUND, 404);
    }

    @Test
    void unexpectedFailureIsRecordedAs500AndRethrown() {
        ProxyExchange exchange = Exchanges.resolved(Exchanges.publicRoute("svc"), Map.of());
        IllegalStateException failure = new IllegalStateException("bug");
        when(chain.proceed(exchange)).thenThrow(failure);

        assertSame(failure, assertThrows(IllegalStateException.class, () -> filter.filter(exchange, chain)));

        verify(audit).record(Exchanges.CLIENT_IP, "GET", "/svc/api", "svc", AccessDecision.FORWARD_FAILED, 500);
        verifyNoMoreInteractions(audit);
    }
}
