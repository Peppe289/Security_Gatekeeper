package io.github.peppe289.security_gatekeeper.gateway.pipeline;

/**
 * Positions of the built-in filters. Gaps leave room for custom filters.
 *
 * <pre>
 *  AUDIT ─▶ ROUTE_RESOLUTION ─▶ ROUTE_ENABLED ─▶ API_KEY ─▶ RATE_LIMIT ─▶ FORWARD
 *  (wraps everything)                                                    (terminal)
 * </pre>
 */
public final class FilterOrder {

    public static final int AUDIT = 0;
    public static final int ROUTE_RESOLUTION = 100;
    public static final int ROUTE_ENABLED = 200;
    public static final int API_KEY = 300;
    public static final int RATE_LIMIT = 400;
    public static final int FORWARD = Integer.MAX_VALUE;

    private FilterOrder() {
    }
}
