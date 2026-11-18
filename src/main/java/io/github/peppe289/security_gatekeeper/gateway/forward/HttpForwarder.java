package io.github.peppe289.security_gatekeeper.gateway.forward;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Sends an authorized exchange to its route's upstream with the JDK
 * {@link HttpClient}. Bodies are streamed in both directions (never fully
 * buffered), so large uploads/downloads use constant memory.
 *
 * <p>Redirects are not followed: they are returned to the client as-is.
 * Upstream TLS certificates are validated with the JVM trust store.
 */
@Component
public class HttpForwarder {

    private static final Logger log = LoggerFactory.getLogger(HttpForwarder.class);

    private final HttpClient client;
    private final Duration responseTimeout;
    private final String apiKeyHeader;
    private final String sessionCookie;

    public HttpForwarder(HttpClient upstreamHttpClient, GatewayProperties properties,
                         @Value("${server.servlet.session.cookie.name:JSESSIONID}") String sessionCookie) {
        this.client = upstreamHttpClient;
        this.responseTimeout = properties.forwarder().responseTimeout();
        this.apiKeyHeader = properties.apiKeyHeader();
        this.sessionCookie = sessionCookie;
    }

    public ForwardResponse forward(ProxyExchange exchange) throws ForwardingException {
        HttpRequest request = buildRequest(exchange);
        String prefix = exchange.routePrefix();
        try {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            return new ForwardResponse(response.statusCode(),
                    ProxyHeaders.forClient(response.headers().map(), sessionCookie), response.body());
        } catch (HttpTimeoutException e) {
            log.warn("Upstream timeout for route '{}': {}", prefix, e.getMessage());
            throw new ForwardingException(504, "Upstream timeout", e);
        } catch (IOException e) {
            log.warn("Upstream unreachable for route '{}': {}", prefix, e.toString());
            throw new ForwardingException(502, "Upstream unreachable", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ForwardingException(502, "Forwarding interrupted", e);
        }
    }

    HttpRequest buildRequest(ProxyExchange exchange) throws ForwardingException {
        try {
            String target = exchange.route().getTargetUrl() + exchange.upstreamPath()
                    + (exchange.rawQuery() == null ? "" : "?" + exchange.rawQuery());
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(target))
                    .timeout(responseTimeout)
                    .method(exchange.method(), bodyPublisher(exchange));
            for (Map.Entry<String, List<String>> h : ProxyHeaders.forUpstream(exchange, apiKeyHeader, sessionCookie).entrySet()) {
                for (String value : h.getValue()) {
                    builder.header(h.getKey(), value);
                }
            }
            return builder.build();
        } catch (IllegalArgumentException e) {
            // malformed URI, method or header value: the client sent something we cannot represent upstream
            throw new ForwardingException(400, "Request cannot be forwarded", e);
        }
    }

    private static HttpRequest.BodyPublisher bodyPublisher(ProxyExchange exchange) {
        if (exchange.contentLength() > 0) {
            return HttpRequest.BodyPublishers.fromPublisher(
                    HttpRequest.BodyPublishers.ofInputStream(exchange::body), exchange.contentLength());
        }
        String te = exchange.header("Transfer-Encoding");
        if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
            return HttpRequest.BodyPublishers.ofInputStream(exchange::body);
        }
        return HttpRequest.BodyPublishers.noBody();
    }
}
