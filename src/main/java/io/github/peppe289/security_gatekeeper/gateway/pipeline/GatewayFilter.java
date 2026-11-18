package io.github.peppe289.security_gatekeeper.gateway.pipeline;

/**
 * One step of the gateway pipeline (chain of responsibility).
 *
 * <p>A filter either short-circuits by returning a
 * {@link ProxyOutcome.Rejected}, or delegates to {@code chain.proceed(exchange)}
 * and may inspect / wrap the result (e.g. auditing). Filters are Spring beans
 * ordered with {@link org.springframework.core.annotation.Order}; see
 * {@link FilterOrder} for the standard positions.
 */
@FunctionalInterface
public interface GatewayFilter {

    ProxyOutcome filter(ProxyExchange exchange, GatewayFilterChain chain);
}
