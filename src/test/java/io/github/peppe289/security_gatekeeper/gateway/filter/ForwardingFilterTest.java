package io.github.peppe289.security_gatekeeper.gateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardResponse;
import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardingException;
import io.github.peppe289.security_gatekeeper.gateway.forward.HttpForwarder;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayFilterChain;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import java.io.ByteArrayInputStream;
import java.net.http.HttpTimeoutException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ForwardingFilterTest {

    @Mock
    private HttpForwarder forwarder;
    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private ForwardingFilter filter;

    private final ProxyExchange exchange = Exchanges.resolved(Exchanges.publicRoute("svc"), Map.of());

    @Test
    void upstreamResponseIsPassedThroughUnchanged() throws Exception {
        ForwardResponse response = new ForwardResponse(418, Map.of("X-Up", List.of("1")),
                new ByteArrayInputStream(new byte[0]));
        when(forwarder.forward(exchange)).thenReturn(response);

        ProxyOutcome outcome = filter.filter(exchange, chain);

        ProxyOutcome.Forwarded forwarded = assertInstanceOf(ProxyOutcome.Forwarded.class, outcome);
        assertSame(response, forwarded.response());
        assertEquals(AccessDecision.ALLOW, outcome.decision());
        assertEquals(418, outcome.status());
        // Terminal filter: there is nothing after it.
        verifyNoInteractions(chain);
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 502, 504})
    void forwardingFailureBecomesARejectionWithItsStatus(int status) throws Exception {
        when(forwarder.forward(exchange))
                .thenThrow(new ForwardingException(status, "upstream failed", new HttpTimeoutException("t")));

        ProxyOutcome outcome = filter.filter(exchange, chain);

        ProxyOutcome.Rejected rejected = assertInstanceOf(ProxyOutcome.Rejected.class, outcome);
        assertEquals(AccessDecision.FORWARD_FAILED, rejected.decision());
        assertEquals(status, rejected.status());
        assertEquals(0, rejected.retryAfterSeconds());
    }
}
