package io.github.peppe289.security_gatekeeper.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.route.RouteDefinition;
import io.github.peppe289.security_gatekeeper.route.RouteService;
import io.github.peppe289.security_gatekeeper.support.EchoUpstream;
import io.github.peppe289.security_gatekeeper.support.IntegrationTest;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

@IntegrationTest
class ProxyIntegrationTest {

    private static final AtomicInteger SEQ = new AtomicInteger();
    private static EchoUpstream upstream;
    private static final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    @Value("${local.server.port}")
    int port;

    @Autowired
    RouteService routes;

    @Autowired
    AuditService audit;

    @BeforeAll
    static void startUpstream() throws IOException {
        upstream = new EchoUpstream();
    }

    @AfterAll
    static void stopUpstream() {
        upstream.close();
    }

    /** Each test uses its own route, so tests are independent within the shared context. */
    private String newRoute(String target, boolean enabled, boolean apiKey, Long burst, Long refill) {
        String prefix = "svc" + SEQ.incrementAndGet();
        RouteService.CreatedRoute created = routes.create(new RouteDefinition(prefix, target, enabled, apiKey, burst, refill));
        return apiKey ? prefix + "|" + created.apiKey() : prefix;
    }

    private HttpResponse<String> send(HttpRequest.Builder builder) throws Exception {
        return http.send(builder.timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
    }

    private static String line(HttpResponse<String> response, String key) {
        for (String l : response.body().split("\n")) {
            if (l.startsWith(key + "=")) {
                return l.substring(key.length() + 1);
            }
        }
        return null;
    }

    @Test
    void forwardsPathQueryAndRewritesHeaders() throws Exception {
        String prefix = newRoute(upstream.url() + "/base", true, false, null, null);
        HttpResponse<String> r = send(request("/" + prefix + "/a/b%20c?x=1&y=%2F")
                .header("X-Custom", "kept")
                .header("X-Forwarded-For", "203.0.113.7")
                .header("X-Api-Key", "must-not-leak")
                .header("Cookie", "GKSESSION=admin-session; theme=dark"));

        assertEquals(200, r.statusCode());
        assertEquals("GET", line(r, "method"));
        assertEquals("/base/a/b%20c", line(r, "path"));
        assertEquals("x=1&y=%2F", line(r, "query"));
        assertEquals("kept", line(r, "header.x-custom"));
        assertEquals("203.0.113.7, 127.0.0.1", line(r, "header.x-forwarded-for"));
        assertEquals("http", line(r, "header.x-forwarded-proto"));
        assertEquals("/" + prefix, line(r, "header.x-forwarded-prefix"));
        assertEquals("localhost:" + port, line(r, "header.x-forwarded-host"));
        assertEquals("theme=dark", line(r, "header.cookie"));
        assertEquals(null, line(r, "header.x-api-key"));

        // response filtering
        assertEquals("echo", r.headers().firstValue("X-Upstream").orElse(null));
        assertEquals(java.util.List.of("app=1; Path=/"), r.headers().allValues("Set-Cookie"));
        assertTrue(r.headers().firstValue("Proxy-Authenticate").isEmpty());
    }

    @Test
    void prefixWithoutTrailingPathHitsUpstreamRoot() throws Exception {
        String prefix = newRoute(upstream.url(), true, false, null, null);
        HttpResponse<String> r = send(request("/" + prefix));
        assertEquals(200, r.statusCode());
        assertEquals("/", line(r, "path"));
    }

    @Test
    void forwardsBodiesAndUpstreamStatus() throws Exception {
        String prefix = newRoute(upstream.url(), true, false, null, null);
        HttpResponse<String> json = send(request("/" + prefix + "/items")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"a\":1}")));
        assertEquals(200, json.statusCode());
        assertEquals("POST", line(json, "method"));
        assertEquals("{\"a\":1}", line(json, "body"));

        // form bodies must reach the upstream untouched (no servlet parameter parsing)
        HttpResponse<String> form = send(request("/" + prefix + "/form")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .method("PUT", HttpRequest.BodyPublishers.ofString("a=1&b=2")));
        assertEquals("PUT", line(form, "method"));
        assertEquals("a=1&b=2", line(form, "body"));

        HttpResponse<String> teapot = send(request("/" + prefix + "/teapot"));
        assertEquals(418, teapot.statusCode());
    }

    @Test
    void unknownRoutesAreNotFound() throws Exception {
        for (String path : new String[]{"/", "/does-not-exist/x", "/Upper/x", "/favicon.ico"}) {
            HttpResponse<String> r = send(request(path));
            assertEquals(404, r.statusCode(), path);
            assertEquals("application/problem+json", r.headers().firstValue("Content-Type").orElse(null));
            assertTrue(r.body().contains("\"status\":404"), r.body());
        }
    }

    @Test
    void disabledRouteIsUnavailable() throws Exception {
        String prefix = newRoute(upstream.url(), false, false, null, null);
        assertEquals(503, send(request("/" + prefix + "/x")).statusCode());
        routes.setEnabled(prefix, true);
        assertEquals(200, send(request("/" + prefix + "/x")).statusCode());
    }

    @Test
    void apiKeyIsEnforced() throws Exception {
        String[] parts = newRoute(upstream.url(), true, true, null, null).split("\\|");
        String prefix = parts[0];
        String key = parts[1];
        assertEquals(401, send(request("/" + prefix + "/x")).statusCode());
        assertEquals(403, send(request("/" + prefix + "/x").header("X-Api-Key", "wrong")).statusCode());
        assertEquals(200, send(request("/" + prefix + "/x").header("X-Api-Key", key)).statusCode());

        routes.removeApiKey(prefix);
        assertEquals(200, send(request("/" + prefix + "/x")).statusCode());
    }

    @Test
    void rateLimitReturns429WithRetryAfter() throws Exception {
        String prefix = newRoute(upstream.url(), true, false, 2L, 1L);
        assertEquals(200, send(request("/" + prefix + "/x")).statusCode());
        assertEquals(200, send(request("/" + prefix + "/x")).statusCode());
        HttpResponse<String> limited = send(request("/" + prefix + "/x"));
        assertEquals(429, limited.statusCode());
        assertEquals("1", limited.headers().firstValue("Retry-After").orElse(null));
    }

    @Test
    void unreachableUpstreamIsBadGateway() throws Exception {
        String prefix = newRoute("http://127.0.0.1:1", true, false, null, null);
        assertEquals(502, send(request("/" + prefix + "/x")).statusCode());
    }

    @Test
    void adminNamespaceIsNeverProxied() throws Exception {
        HttpResponse<String> r = send(request("/_gatekeeper/"));
        assertEquals(302, r.statusCode());
        assertTrue(r.headers().firstValue("Location").orElse("").endsWith("/_gatekeeper/login"));
    }

    @Test
    void requestsAreAuditedAndChainVerifies() throws Exception {
        String prefix = newRoute(upstream.url(), true, false, null, null);
        long before = audit.stats().persisted();
        send(request("/" + prefix + "/audited?secret=token"));
        long deadline = System.currentTimeMillis() + 5000;
        while (audit.stats().persisted() <= before && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        var latest = audit.latest(200).stream()
                .filter(s -> s.record().getRoutePrefix().equals(prefix))
                .findFirst()
                .orElse(null);
        assertNotNull(latest);
        assertEquals("/" + prefix + "/audited", latest.record().getPath(), "query string is not recorded");
        assertEquals("ALLOW", latest.record().getDecision());
        assertEquals(200, latest.record().getHttpStatus());
        assertEquals("test-node", latest.nodeId());

        AuditService.IntegrityReport report = audit.verifyAll();
        assertTrue(report.valid());
        assertTrue(report.checkedRecords() > 0);
        assertFalse(report.brokenNode() != null);
    }
}
