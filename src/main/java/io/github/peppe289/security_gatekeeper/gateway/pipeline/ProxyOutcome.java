package io.github.peppe289.security_gatekeeper.gateway.pipeline;

import io.github.peppe289.security_gatekeeper.core.routing.AccessDecision;
import io.github.peppe289.security_gatekeeper.gateway.forward.ForwardResponse;

/**
 * Result of the pipeline: either the upstream response, or a rejection
 * produced by one of the filters.
 */
public sealed interface ProxyOutcome permits ProxyOutcome.Forwarded, ProxyOutcome.Rejected {

    AccessDecision decision();

    int status();

    record Forwarded(ForwardResponse response) implements ProxyOutcome {
        @Override
        public AccessDecision decision() {
            return AccessDecision.ALLOW;
        }

        @Override
        public int status() {
            return response.status();
        }
    }

    /**
     * @param retryAfterSeconds value for {@code Retry-After}, {@code 0} for none
     */
    record Rejected(AccessDecision decision, int status, long retryAfterSeconds) implements ProxyOutcome {

        public static Rejected of(AccessDecision decision) {
            return new Rejected(decision, decision.httpStatus(), 0);
        }
    }
}
