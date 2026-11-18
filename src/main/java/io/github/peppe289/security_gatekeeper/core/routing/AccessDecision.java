package io.github.peppe289.security_gatekeeper.core.routing;

/**
 * Outcome of the gateway pipeline for one request, with its default HTTP status.
 */
public enum AccessDecision {
    ALLOW(200, "Allowed"),
    ROUTE_NOT_FOUND(404, "No route registered for this prefix"),
    ROUTE_DISABLED(503, "Route temporarily disabled"),
    API_KEY_MISSING(401, "API key required"),
    API_KEY_INVALID(403, "Invalid API key"),
    RATE_LIMITED(429, "Rate limit exceeded"),
    /** Allowed by every check, but the upstream could not be reached (502/504) or the request not represented (400). */
    FORWARD_FAILED(502, "Upstream unavailable");

    private final int httpStatus;
    private final String reason;

    AccessDecision(int httpStatus, String reason) {
        this.httpStatus = httpStatus;
        this.reason = reason;
    }

    public int httpStatus() {
        return httpStatus;
    }

    /** Client-safe, constant description (never contains request data). */
    public String reason() {
        return reason;
    }

    public boolean isAllowed() {
        return this == ALLOW;
    }
}
