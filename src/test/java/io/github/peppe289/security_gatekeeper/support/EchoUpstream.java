package io.github.peppe289.security_gatekeeper.support;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal upstream for tests: echoes what it received, one {@code key=value}
 * per line, and sets a few headers the gateway must filter.
 */
public final class EchoUpstream implements AutoCloseable {

    private final HttpServer server;

    public EchoUpstream() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body;
            try (InputStream in = exchange.getRequestBody()) {
                body = in.readAllBytes();
            }
            StringBuilder sb = new StringBuilder();
            sb.append("method=").append(exchange.getRequestMethod()).append('\n');
            sb.append("path=").append(exchange.getRequestURI().getRawPath()).append('\n');
            sb.append("query=").append(exchange.getRequestURI().getRawQuery()).append('\n');
            Map<String, List<String>> sorted = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            sorted.putAll(exchange.getRequestHeaders());
            sorted.forEach((k, v) -> sb.append("header.").append(k.toLowerCase()).append('=')
                    .append(String.join(",", v)).append('\n'));
            sb.append("body=").append(new String(body, StandardCharsets.UTF_8)).append('\n');

            exchange.getResponseHeaders().add("X-Upstream", "echo");
            exchange.getResponseHeaders().add("Set-Cookie", "app=1; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "GKSESSION=attacker; Path=/");
            exchange.getResponseHeaders().add("Proxy-Authenticate", "Basic");
            int status = exchange.getRequestURI().getPath().endsWith("/teapot") ? 418 : 200;
            byte[] out = sb.toString().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
