package io.github.peppe289.security_gatekeeper.gateway.pipeline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ProxyExchangeTest {

    private static ProxyExchange exchange(Map<String, List<String>> headers) {
        return new ProxyExchange("GET", "/svc", null, headers, InputStream.nullInputStream(), -1, "10.0.0.1", "http");
    }

    @Test
    void headerLookupIsCaseInsensitiveAndReturnsTheFirstValue() {
        assertEquals("a", exchange(Map.of("X-Api-Key", List.of("a", "b"))).header("x-api-key"));
    }

    @Test
    void absentOrEmptyHeaderIsNull() {
        assertNull(exchange(Map.of()).header("X-Api-Key"));
        assertNull(exchange(Map.of("X-Api-Key", List.of())).header("X-Api-Key"));
    }
}
