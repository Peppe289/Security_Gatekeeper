package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.sun.net.httpserver.HttpServer;

import io.github.peppe289.security_gatekeeper.SecurityGatekeeperApplication;
import io.github.peppe289.security_gatekeeper.route.RouteDefinition;
import io.github.peppe289.security_gatekeeper.route.RouteService;

/**
 * A request still in flight when the application shuts down must be audited.
 *
 * <p>With {@code server.shutdown: graceful}, Tomcat lets in-flight requests finish before it
 * stops; the audit writer must still be running at that point, or the events of those requests
 * are queued after it has exited and never persisted. This test runs its own application
 * context (not the shared one of {@code @IntegrationTest}) because it closes it.
 */
class AuditShutdownIntegrationTest {

    private static final String NODE = "shutdown-node";
    private static final String PATH = "/slow/in-flight";

    private static PostgreSQLContainer postgres;

    @BeforeAll
    static void startDatabase() {
        postgres = new PostgreSQLContainer("postgres:18-alpine");
        postgres.start();
    }

    @AfterAll
    static void stopDatabase() {
        postgres.stop();
    }

    @Test
    void requestInFlightDuringShutdownIsAudited() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        HttpServer upstream = slowUpstream(received, release);
        try {
            // Command-line arguments: unlike builder defaults, they override application.yml.
            ConfigurableApplicationContext context = new SpringApplicationBuilder(SecurityGatekeeperApplication.class)
                    .run("--server.port=0",
                            "--spring.datasource.url=" + postgres.getJdbcUrl(),
                            "--spring.datasource.username=" + postgres.getUsername(),
                            "--spring.datasource.password=" + postgres.getPassword(),
                            "--gateway.node-id=" + NODE,
                            "--gateway.admin.password=test-admin-password",
                            "--gateway.audit.hmac-key=test-audit-hmac-key-0123456789abcdef",
                            "--gateway.audit.flush-interval=20ms");
            int port = ((WebServerApplicationContext) context).getWebServer().getPort();
            context.getBean(RouteService.class).create(new RouteDefinition("slow",
                    "http://127.0.0.1:" + upstream.getAddress().getPort(), true, false, null, null));

            CompletableFuture<HttpResponse<String>> inFlight = HttpClient.newHttpClient().sendAsync(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + PATH))
                            .timeout(Duration.ofSeconds(30)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(received.await(10, TimeUnit.SECONDS), "upstream never received the request");

            // Shut down while the request is still waiting for the upstream.
            CompletableFuture<Void> shutdown = CompletableFuture.runAsync(context::close);
            // Graceful shutdown has begun once Tomcat stops accepting new connections.
            awaitTrue(() -> !accepts(port), "server kept accepting connections");
            release.countDown();

            assertEquals(200, inFlight.get(30, TimeUnit.SECONDS).statusCode());
            shutdown.get(60, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            upstream.stop(0);
        }

        assertEquals(1, auditedRows(PATH), "the in-flight request was not persisted in the audit log");
    }

    private static HttpServer slowUpstream(CountDownLatch received, CountDownLatch release) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            received.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        return server;
    }

    private static boolean accepts(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void awaitTrue(BooleanSupplier condition, String message) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError(message);
            }
            Thread.sleep(20);
        }
    }

    private static int auditedRows(String path) throws Exception {
        try (Connection c = DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(),
                postgres.getPassword());
             PreparedStatement ps = c.prepareStatement(
                     "SELECT count(*) FROM audit_log WHERE node_id = ? AND path = ?")) {
            ps.setString(1, NODE);
            ps.setString(2, path);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }
}
