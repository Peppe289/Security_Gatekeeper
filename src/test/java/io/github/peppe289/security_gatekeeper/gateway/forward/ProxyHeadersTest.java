package io.github.peppe289.security_gatekeeper.gateway.forward;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Header rewriting in both directions (RFC 9110 §7.6.1), without any network. */
class ProxyHeadersTest {

    private static final String API_KEY_HEADER = "X-Api-Key";
    private static final String SESSION_COOKIE = "GKSESSION";

    private static ProxyExchange exchange(Map<String, List<String>> headers) {
        ProxyExchange exchange = new ProxyExchange("GET", "/svc/x", null, headers, InputStream.nullInputStream(),
                -1, "203.0.113.7", "https");
        exchange.resolveRoute("svc", new RoutePolicy("svc", "http://upstream", true, null, 10, 10), "/x");
        return exchange;
    }

    /** Case-insensitive lookup, as HTTP header names are. */
    private static List<String> get(Map<String, List<String>> headers, String name) {
        Map<String, List<String>> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        ci.putAll(headers);
        return ci.get(name);
    }

    @Nested
    class ToUpstream {

        private Map<String, List<String>> upstream(Map<String, List<String>> clientHeaders) {
            return ProxyHeaders.forUpstream(exchange(clientHeaders), API_KEY_HEADER, SESSION_COOKIE);
        }

        @Test
        void endToEndHeadersAreKept() {
            Map<String, List<String>> out = upstream(Map.of("Accept", List.of("text/html"),
                    "X-Custom", List.of("a", "b")));

            assertEquals(List.of("text/html"), get(out, "Accept"));
            assertEquals(List.of("a", "b"), get(out, "X-Custom"));
        }

        @Test
        void hopByHopHeadersAreDropped() {
            Map<String, List<String>> in = new LinkedHashMap<>();
            for (String name : ProxyHeaders.HOP_BY_HOP) {
                in.put(name, List.of("x"));
            }
            Map<String, List<String>> out = upstream(in);

            for (String name : ProxyHeaders.HOP_BY_HOP) {
                assertNull(get(out, name), name);
            }
        }

        @Test
        void headersNamedInConnectionAreDropped() {
            Map<String, List<String>> out = upstream(Map.of(
                    "Connection", List.of("X-Secret, x-other"),
                    "X-Secret", List.of("1"),
                    "X-Other", List.of("2"),
                    "X-Kept", List.of("3")));

            assertNull(get(out, "X-Secret"));
            assertNull(get(out, "X-Other"));
            assertEquals(List.of("3"), get(out, "X-Kept"));
        }

        @Test
        void clientManagedHeadersAreNotCopied() {
            Map<String, List<String>> out = upstream(Map.of(
                    "Host", List.of("public.example"),
                    "Content-Length", List.of("10"),
                    "Expect", List.of("100-continue")));

            assertNull(get(out, "Host"));
            assertNull(get(out, "Content-Length"));
            assertNull(get(out, "Expect"));
        }

        @Test
        void apiKeyNeverReachesTheUpstream() {
            Map<String, List<String>> out = upstream(Map.of("x-api-key", List.of("gk_secret")));
            assertNull(get(out, API_KEY_HEADER));
        }

        @Test
        void sessionCookieIsRemovedAndOtherCookiesKept() {
            Map<String, List<String>> out = upstream(Map.of("Cookie",
                    List.of("app=1; GKSESSION=abc; theme=dark")));

            assertEquals(List.of("app=1; theme=dark"), get(out, "Cookie"));
        }

        @Test
        void cookieHeaderWithOnlyTheSessionIsDropped() {
            Map<String, List<String>> out = upstream(Map.of("Cookie", List.of("GKSESSION=abc")));
            assertNull(get(out, "Cookie"));
        }

        @Test
        void forwardedHeadersDescribeTheClient() {
            Map<String, List<String>> out = upstream(Map.of("Host", List.of("public.example")));

            assertEquals(List.of("203.0.113.7"), get(out, "X-Forwarded-For"));
            assertEquals(List.of("https"), get(out, "X-Forwarded-Proto"));
            assertEquals(List.of("public.example"), get(out, "X-Forwarded-Host"));
            assertEquals(List.of("/svc"), get(out, "X-Forwarded-Prefix"));
        }

        @Test
        void clientAddressIsAppendedToAnExistingForwardedForChain() {
            Map<String, List<String>> out = upstream(Map.of("X-Forwarded-For", List.of("198.51.100.1")));
            assertEquals(List.of("198.51.100.1, 203.0.113.7"), get(out, "X-Forwarded-For"));
        }

        @Test
        void spoofedForwardedHeadersAreOverwritten() {
            Map<String, List<String>> out = upstream(Map.of(
                    "X-Forwarded-Proto", List.of("http"),
                    "X-Forwarded-Prefix", List.of("/admin")));

            assertEquals(List.of("https"), get(out, "X-Forwarded-Proto"));
            assertEquals(List.of("/svc"), get(out, "X-Forwarded-Prefix"));
        }

        @Test
        void withoutHostThereIsNoForwardedHost() {
            assertNull(get(upstream(Map.of()), "X-Forwarded-Host"));
        }
    }

    @Nested
    class ToClient {

        private Map<String, List<String>> client(Map<String, List<String>> upstreamHeaders) {
            return ProxyHeaders.forClient(upstreamHeaders, SESSION_COOKIE);
        }

        @Test
        void hopByHopConnectionListedAndPseudoHeadersAreDropped() {
            Map<String, List<String>> out = client(Map.of(
                    "Transfer-Encoding", List.of("chunked"),
                    "Connection", List.of("X-Internal"),
                    "X-Internal", List.of("1"),
                    ":status", List.of("200"),
                    "Content-Type", List.of("text/plain")));

            assertEquals(Set.of("Content-Type"), out.keySet());
        }

        @Test
        void upstreamCannotSetTheGatewaySessionCookie() {
            Map<String, List<String>> out = client(Map.of("Set-Cookie",
                    List.of("app=1; Path=/", "GKSESSION=attacker; Path=/")));

            assertEquals(List.of("app=1; Path=/"), get(out, "Set-Cookie"));
        }

        @Test
        void setCookieWithOnlyTheSessionIsDropped() {
            Map<String, List<String>> out = client(Map.of("Set-Cookie", List.of("GKSESSION=attacker")));
            assertFalse(out.containsKey("Set-Cookie"));
        }
    }

    @Nested
    class StripCookie {

        @Test
        void removesOnlyTheNamedCookie() {
            assertEquals("a=1; b=2", ProxyHeaders.stripCookie("a=1; GKSESSION=x; b=2", SESSION_COOKIE));
        }

        @Test
        void cookieWhoseNameOnlyStartsTheSameIsKept() {
            assertEquals("GKSESSION2=x", ProxyHeaders.stripCookie("GKSESSION2=x", SESSION_COOKIE));
        }

        @Test
        void emptyPairsAndValuelessCookiesAreHandled() {
            assertEquals("flag", ProxyHeaders.stripCookie(" ; flag;; GKSESSION", SESSION_COOKIE));
            assertTrue(ProxyHeaders.stripCookie("GKSESSION=x", SESSION_COOKIE).isEmpty());
        }
    }
}
