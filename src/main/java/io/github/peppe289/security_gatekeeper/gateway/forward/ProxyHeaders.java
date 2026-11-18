package io.github.peppe289.security_gatekeeper.gateway.forward;

import io.github.peppe289.security_gatekeeper.gateway.pipeline.ProxyExchange;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Header rewriting rules for a reverse proxy (RFC 9110 §7.6.1).
 *
 * <ul>
 *   <li>Hop-by-hop headers, and any header named in {@code Connection}, are
 *       dropped in both directions.</li>
 *   <li>Headers managed by the HTTP client ({@code Host}, {@code Content-Length},
 *       {@code Expect}) are not copied.</li>
 *   <li>Gateway credentials never reach the upstream: the API-key header and
 *       the gateway's own session cookie are removed.</li>
 *   <li>{@code X-Forwarded-For/Proto/Host/Prefix} are (re)written.</li>
 *   <li>An upstream cannot set the gateway's session cookie (prevents session
 *       fixation of the admin dashboard by a malicious upstream).</li>
 * </ul>
 */
public final class ProxyHeaders {

    static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade");

    /** Set by the JDK HttpClient itself (setting them throws) or rebuilt by us. */
    private static final Set<String> REQUEST_MANAGED = Set.of(
            "host", "content-length", "expect",
            "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-prefix");

    private ProxyHeaders() {
    }

    public static Map<String, List<String>> forUpstream(ProxyExchange req, String apiKeyHeader, String sessionCookie) {
        Set<String> excluded = excludedNames(req.headers());
        excluded.addAll(REQUEST_MANAGED);
        excluded.add(apiKeyHeader.toLowerCase(Locale.ROOT));

        Map<String, List<String>> out = new LinkedHashMap<>();
        List<String> previousForwardedFor = new ArrayList<>();
        String host = null;
        for (Map.Entry<String, List<String>> e : req.headers().entrySet()) {
            String name = e.getKey().toLowerCase(Locale.ROOT);
            if (name.equals("x-forwarded-for")) {
                previousForwardedFor.addAll(e.getValue());
            } else if (name.equals("host") && !e.getValue().isEmpty()) {
                host = e.getValue().get(0);
            } else if (name.equals("cookie")) {
                List<String> kept = new ArrayList<>();
                for (String v : e.getValue()) {
                    String filtered = stripCookie(v, sessionCookie);
                    if (!filtered.isEmpty()) {
                        kept.add(filtered);
                    }
                }
                if (!kept.isEmpty()) {
                    out.put(e.getKey(), kept);
                }
            } else if (!excluded.contains(name)) {
                out.put(e.getKey(), List.copyOf(e.getValue()));
            }
        }
        previousForwardedFor.add(req.clientIp());
        out.put("X-Forwarded-For", List.of(String.join(", ", previousForwardedFor)));
        out.put("X-Forwarded-Proto", List.of(req.scheme()));
        if (host != null) {
            out.put("X-Forwarded-Host", List.of(host));
        }
        out.put("X-Forwarded-Prefix", List.of("/" + req.routePrefix()));
        return out;
    }

    public static Map<String, List<String>> forClient(Map<String, List<String>> upstreamHeaders, String sessionCookie) {
        Set<String> excluded = excludedNames(upstreamHeaders);
        excluded.add(":status"); // HTTP/2 pseudo-header exposed by some clients
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : upstreamHeaders.entrySet()) {
            String name = e.getKey().toLowerCase(Locale.ROOT);
            if (excluded.contains(name)) {
                continue;
            }
            List<String> values = e.getValue();
            if (name.equals("set-cookie")) {
                values = values.stream().filter(v -> !cookieName(v).equals(sessionCookie)).toList();
            }
            if (!values.isEmpty()) {
                out.put(e.getKey(), List.copyOf(values));
            }
        }
        return out;
    }

    /** Hop-by-hop names plus every token listed in the {@code Connection} header(s). */
    private static Set<String> excludedNames(Map<String, List<String>> headers) {
        Set<String> excluded = new HashSet<>(HOP_BY_HOP);
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase("connection")) {
                for (String v : e.getValue()) {
                    for (String token : v.split(",")) {
                        excluded.add(token.trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
        }
        return excluded;
    }

    /** Removes {@code name=value} pairs named {@code cookieName} from a {@code Cookie} header value. */
    static String stripCookie(String cookieHeader, String cookieName) {
        List<String> kept = new ArrayList<>();
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            if (!trimmed.isEmpty() && !cookieName(trimmed).equals(cookieName)) {
                kept.add(trimmed);
            }
        }
        return String.join("; ", kept);
    }

    private static String cookieName(String cookie) {
        int eq = cookie.indexOf('=');
        return (eq < 0 ? cookie : cookie.substring(0, eq)).trim();
    }
}
