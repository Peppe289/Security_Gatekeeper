package io.github.peppe289.security_gatekeeper.gateway;

import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardResponse;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayPipeline;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyOutcome;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Servlet entry point of the reverse proxy. Every request outside the admin
 * namespace ({@value #ADMIN_PATH}) is converted into a {@link ProxyExchange},
 * run through the {@link GatewayPipeline} and answered directly, without
 * reaching Spring MVC.
 *
 * <p>Registered after Spring Security, so the request has already passed the
 * HTTP firewall (path normalization, encoded traversal rejection).
 */
public class ProxyEntryFilter extends OncePerRequestFilter {

    public static final String ADMIN_PATH = "/_gatekeeper";

    private static final Logger log = LoggerFactory.getLogger(ProxyEntryFilter.class);

    private final GatewayPipeline pipeline;

    public ProxyEntryFilter(GatewayPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = pathWithinApp(request);
        return path.equals(ADMIN_PATH) || path.startsWith(ADMIN_PATH + "/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        ProxyExchange exchange = new ProxyExchange(request.getMethod(), pathWithinApp(request), request.getQueryString(),
                headers(request), request.getInputStream(), request.getContentLengthLong(), request.getRemoteAddr(),
                request.getScheme());

        ProxyOutcome outcome = pipeline.execute(exchange);
        if (outcome instanceof ProxyOutcome.Forwarded forwarded) {
            writeUpstreamResponse(forwarded.response(), response);
        } else if (outcome instanceof ProxyOutcome.Rejected rejected) {
            writeRejection(rejected, response);
        }
    }

    private static void writeUpstreamResponse(ForwardResponse upstream, HttpServletResponse response) throws IOException {
        response.setStatus(upstream.status());
        upstream.headers().forEach((name, values) -> values.forEach(v -> response.addHeader(name, v)));
        try (InputStream in = upstream.body(); OutputStream out = response.getOutputStream()) {
            in.transferTo(out);
        } catch (IOException e) {
            // typically the client went away mid-transfer; nothing left to answer
            log.debug("Response streaming aborted: {}", e.toString());
        }
    }

    /** RFC 9457 problem document. All values are constants: no request data is echoed back. */
    private static void writeRejection(ProxyOutcome.Rejected rejected, HttpServletResponse response) throws IOException {
        HttpStatus status = HttpStatus.resolve(rejected.status());
        String title = status == null ? "Error" : status.getReasonPhrase();
        String body = "{\"type\":\"about:blank\",\"title\":\"" + title + "\",\"status\":" + rejected.status()
                + ",\"detail\":\"" + rejected.decision().reason() + "\"}";
        response.setStatus(rejected.status());
        response.setContentType("application/problem+json");
        response.setHeader("Cache-Control", "no-store");
        if (rejected.retryAfterSeconds() > 0) {
            response.setHeader("Retry-After", Long.toString(rejected.retryAfterSeconds()));
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    private static Map<String, List<String>> headers(HttpServletRequest request) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            headers.put(name, Collections.list(request.getHeaders(name)));
        }
        return headers;
    }

    private static String pathWithinApp(HttpServletRequest request) {
        return request.getRequestURI().substring(request.getContextPath().length());
    }
}
