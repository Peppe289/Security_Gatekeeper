package io.github.peppe289.security_gatekeeper.gateway.pipeline;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * One request travelling through the gateway pipeline: immutable request data
 * (servlet-independent) plus the attributes filters attach along the way.
 */
public final class ProxyExchange {

    private final String method;
    private final String path;
    private final String rawQuery;
    private final Map<String, List<String>> headers;
    private final InputStream body;
    private final long contentLength;
    private final String clientIp;
    private final String scheme;

    private String routePrefix = "";
    private RoutePolicy route;
    private String upstreamPath = "";

    /**
     * @param path          raw (still percent-encoded) request path, without query string
     * @param rawQuery      raw query string or {@code null}
     * @param contentLength declared body length, {@code -1} if unknown
     */
    public ProxyExchange(String method, String path, String rawQuery, Map<String, List<String>> headers,
                         InputStream body, long contentLength, String clientIp, String scheme) {
        this.method = Objects.requireNonNull(method);
        this.path = Objects.requireNonNull(path);
        this.rawQuery = rawQuery;
        TreeMap<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.forEach((k, v) -> copy.put(k, List.copyOf(v)));
        this.headers = Collections.unmodifiableMap(copy);
        this.body = Objects.requireNonNull(body);
        this.contentLength = contentLength;
        this.clientIp = Objects.requireNonNull(clientIp);
        this.scheme = Objects.requireNonNull(scheme);
    }

    /** @return first value of the header (case-insensitive), or {@code null} */
    public String header(String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    public String rawQuery() {
        return rawQuery;
    }

    /** Case-insensitive, unmodifiable view. */
    public Map<String, List<String>> headers() {
        return headers;
    }

    public InputStream body() {
        return body;
    }

    public long contentLength() {
        return contentLength;
    }

    public String clientIp() {
        return clientIp;
    }

    public String scheme() {
        return scheme;
    }

    /** Requested route prefix (first path segment) if syntactically valid, else empty. */
    public String routePrefix() {
        return routePrefix;
    }

    /** Resolved route, {@code null} until {@code RouteResolutionFilter} has run. */
    public RoutePolicy route() {
        return route;
    }

    /** Path to request upstream: what follows {@code /{prefix}}, empty or starting with {@code /}. */
    public String upstreamPath() {
        return upstreamPath;
    }

    public void resolveRoute(String routePrefix, RoutePolicy route, String upstreamPath) {
        this.routePrefix = Objects.requireNonNull(routePrefix);
        this.route = route;
        this.upstreamPath = Objects.requireNonNull(upstreamPath);
    }
}
