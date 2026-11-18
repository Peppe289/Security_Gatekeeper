package io.github.peppe289.security_gatekeeper.route;

/**
 * Domain exceptions raised by {@link RouteService}. Their messages are
 * constant or built from validated data only, so they are safe to show in the
 * dashboard.
 */
public final class RouteExceptions {

    private RouteExceptions() {
    }

    public static class RouteNotFoundException extends RuntimeException {
        public RouteNotFoundException() {
            super("Route not found");
        }
    }

    public static class RouteAlreadyExistsException extends RuntimeException {
        public RouteAlreadyExistsException() {
            super("A route with this prefix already exists");
        }
    }

    public static class InvalidRouteException extends RuntimeException {
        public InvalidRouteException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
