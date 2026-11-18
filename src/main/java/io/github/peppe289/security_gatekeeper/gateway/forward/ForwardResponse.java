package io.github.peppe289.security_gatekeeper.gateway.forward;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Upstream response, already filtered of hop-by-hop headers. The body is
 * streamed: the caller must close it.
 */
public record ForwardResponse(int status, Map<String, List<String>> headers, InputStream body) {
}
