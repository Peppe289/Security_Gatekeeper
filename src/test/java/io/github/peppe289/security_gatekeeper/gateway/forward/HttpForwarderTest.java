package io.github.peppe289.security_gatekeeper.gateway.forward;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Request construction and error mapping, with the JDK HTTP client mocked: no network involved. */
@ExtendWith(MockitoExtension.class)
class HttpForwarderTest {

    private static final RoutePolicy ROUTE = new RoutePolicy("svc", "http://upstream:8080/base", true, null, 10, 10);

    @Mock
    private HttpClient client;
    @Mock
    private HttpResponse<InputStream> response;

    private HttpForwarder forwarder;

    @BeforeEach
    void setUp() {
        forwarder = new HttpForwarder(client, TestProperties.defaults(), "GKSESSION");
    }

    private static ProxyExchange exchange(String method, String query, Map<String, List<String>> headers,
                                          long contentLength) {
        ProxyExchange exchange = new ProxyExchange(method, "/svc/a/b", query, headers,
                new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8)), contentLength, "10.0.0.1", "http");
        exchange.resolveRoute("svc", ROUTE, "/a/b");
        return exchange;
    }

    private static ProxyExchange get() {
        return exchange("GET", null, Map.of(), -1);
    }

    @Nested
    class BuildRequest {

        @Test
        void targetIsTheRouteUrlPlusTheRemainingPath() throws Exception {
            HttpRequest request = forwarder.buildRequest(get());

            assertEquals(URI.create("http://upstream:8080/base/a/b"), request.uri());
            assertEquals("GET", request.method());
            assertEquals(Duration.ofSeconds(60), request.timeout().orElseThrow());
        }

        @Test
        void rawQueryIsForwardedUnchanged() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("GET", "x=1&y=%2F", Map.of(), -1));
            assertEquals("x=1&y=%2F", request.uri().getRawQuery());
        }

        @Test
        void rewrittenHeadersAreApplied() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("GET", null,
                    Map.of("X-Custom", List.of("1"), "X-Api-Key", List.of("gk_secret")), -1));

            assertEquals(List.of("1"), request.headers().allValues("X-Custom"));
            assertTrue(request.headers().allValues("X-Api-Key").isEmpty());
            assertEquals(List.of("10.0.0.1"), request.headers().allValues("X-Forwarded-For"));
        }

        @Test
        void declaredLengthIsStreamedWithThatLength() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("POST", null, Map.of(), 5));
            assertEquals(5, request.bodyPublisher().orElseThrow().contentLength());
        }

        @Test
        void chunkedBodyIsStreamedWithUnknownLength() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("POST", null,
                    Map.of("Transfer-Encoding", List.of("Chunked")), -1));
            assertEquals(-1, request.bodyPublisher().orElseThrow().contentLength());
        }

        @Test
        void transferEncodingOtherThanChunkedMeansNoBody() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("POST", null,
                    Map.of("Transfer-Encoding", List.of("gzip")), -1));
            assertEquals(0, request.bodyPublisher().orElseThrow().contentLength());
        }

        @Test
        void noLengthAndNoChunkingMeansNoBody() throws Exception {
            HttpRequest request = forwarder.buildRequest(exchange("POST", null, Map.of(), -1));
            assertEquals(0, request.bodyPublisher().orElseThrow().contentLength());
        }

        @Test
        void requestThatWouldLeaveTheUpstreamIsA400() {
            // The resolution filter never produces such a path; the forwarder refuses it anyway.
            RoutePolicy hostOnly = new RoutePolicy("svc", "http://upstream:8080", true, null, 10, 10);
            ProxyExchange exchange = new ProxyExchange("GET", "/svc", null, Map.of(), InputStream.nullInputStream(),
                    -1, "10.0.0.1", "http");
            exchange.resolveRoute("svc", hostOnly, "@evil.example/steal");

            ForwardingException e = assertThrows(ForwardingException.class, () -> forwarder.buildRequest(exchange));
            assertEquals(400, e.status());
        }

        @Test
        void sameOriginCheck() throws Exception {
            URI route = URI.create("http://upstream:8080/base");
            HttpForwarder.requireSameOrigin(URI.create("http://UPSTREAM:8080/base/x?y=1"), route);
            for (String other : List.of("https://upstream:8080/base", "http://upstream:9090/base",
                    "http://evil:8080/base", "http://user@upstream:8080/base")) {
                assertThrows(ForwardingException.class, () -> HttpForwarder.requireSameOrigin(URI.create(other), route),
                        other);
            }
        }

        @Test
        void unrepresentableRequestIsA400() {
            ProxyExchange invalidMethod = exchange("GE T", null, Map.of(), -1);

            ForwardingException e = assertThrows(ForwardingException.class,
                    () -> forwarder.buildRequest(invalidMethod));
            assertEquals(400, e.status());
        }
    }

    @Nested
    class Forward {

        @Test
        void upstreamResponseIsReturnedWithFilteredHeaders() throws Exception {
            InputStream body = new ByteArrayInputStream(new byte[] {1, 2, 3});
            doReturn(response).when(client).send(any(HttpRequest.class), any());
            when(response.statusCode()).thenReturn(201);
            when(response.headers()).thenReturn(HttpHeaders.of(Map.of(
                    "Content-Type", List.of("text/plain"),
                    "Connection", List.of("close"),
                    "Set-Cookie", List.of("GKSESSION=attacker")), (name, value) -> true));
            when(response.body()).thenReturn(body);

            ForwardResponse result = forwarder.forward(get());

            Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.putAll(result.headers());
            assertEquals(201, result.status());
            assertEquals(List.of("text/plain"), headers.get("content-type"));
            assertFalse(headers.containsKey("connection"));
            assertNull(headers.get("set-cookie"));
            assertSame(body, result.body());
        }

        @Test
        void upstreamTimeoutIsA504() throws Exception {
            when(client.send(any(HttpRequest.class), any())).thenThrow(new HttpTimeoutException("slow"));
            assertEquals(504, assertThrows(ForwardingException.class, () -> forwarder.forward(get())).status());
        }

        @Test
        void unreachableUpstreamIsA502() throws Exception {
            when(client.send(any(HttpRequest.class), any())).thenThrow(new IOException("refused"));
            assertEquals(502, assertThrows(ForwardingException.class, () -> forwarder.forward(get())).status());
        }

        @Nested
        class Interrupted {

            @AfterEach
            void clearInterruptFlag() {
                Thread.interrupted();
            }

            @Test
            void interruptionIsA502AndTheFlagIsRestored() throws Exception {
                when(client.send(any(HttpRequest.class), any())).thenThrow(new InterruptedException());

                ForwardingException e = assertThrows(ForwardingException.class, () -> forwarder.forward(get()));

                assertEquals(502, e.status());
                assertTrue(Thread.currentThread().isInterrupted());
            }
        }
    }
}
