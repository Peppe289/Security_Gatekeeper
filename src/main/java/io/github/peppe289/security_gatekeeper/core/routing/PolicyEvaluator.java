package io.github.peppe289.security_gatekeeper.core.routing;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;

/**
 * Stateless route checks, one per gateway filter, applied in pipeline order:
 * route exists, route enabled, API key.
 */
public final class PolicyEvaluator {

    private PolicyEvaluator() {
    }

    /*@ public normal_behavior
      @   ensures policy == null ==> \result == AccessDecision.ROUTE_NOT_FOUND;
      @   ensures policy != null ==> \result == AccessDecision.ALLOW;
      @ pure
      @*/
    public static AccessDecision checkExists(/*@ nullable @*/ RoutePolicy policy) {
        return policy == null ? AccessDecision.ROUTE_NOT_FOUND : AccessDecision.ALLOW;
    }

    /*@ public normal_behavior
      @   requires policy != null;
      @   ensures \result == (policy.enabled ? AccessDecision.ALLOW : AccessDecision.ROUTE_DISABLED);
      @ pure
      @*/
    public static AccessDecision checkEnabled(RoutePolicy policy) {
        return policy.isEnabled() ? AccessDecision.ALLOW : AccessDecision.ROUTE_DISABLED;
    }

    /*@ public normal_behavior
      @   requires policy != null;
      @   ensures policy.apiKeyHash == null ==> \result == AccessDecision.ALLOW;
      @   ensures policy.apiKeyHash != null && (presentedApiKey == null || presentedApiKey.isEmpty())
      @             ==> \result == AccessDecision.API_KEY_MISSING;
      @   ensures \result == AccessDecision.ALLOW || \result == AccessDecision.API_KEY_MISSING
      @             || \result == AccessDecision.API_KEY_INVALID;
      @ pure
      @*/
    public static AccessDecision checkApiKey(RoutePolicy policy, /*@ nullable @*/ String presentedApiKey) {
        if (!policy.requiresApiKey()) {
            return AccessDecision.ALLOW;
        }
        if (presentedApiKey == null || presentedApiKey.isEmpty()) {
            return AccessDecision.API_KEY_MISSING;
        }
        boolean valid = Sha256.constantTimeEquals(Sha256.hex(presentedApiKey), policy.getApiKeyHash());
        return valid ? AccessDecision.ALLOW : AccessDecision.API_KEY_INVALID;
    }
}
