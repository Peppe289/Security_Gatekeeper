package io.github.peppe289.security_gatekeeper.core.routing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class PolicyEvaluatorTest {

    private static final RoutePolicy PUBLIC = new RoutePolicy("pub", "http://h", true, null, 1, 1);
    private static final RoutePolicy KEYED = new RoutePolicy("sec", "http://h", true, Sha256.hex("s3cret"), 1, 1);

    @Test
    void unknownRouteIsNotFound() {
        assertEquals(AccessDecision.ROUTE_NOT_FOUND, PolicyEvaluator.checkExists(null));
    }

    @Test
    void disabledRouteIsRejected() {
        assertEquals(AccessDecision.ROUTE_DISABLED, PolicyEvaluator.checkEnabled(PUBLIC.withEnabled(false)));
        assertEquals(AccessDecision.ROUTE_DISABLED, PolicyEvaluator.checkEnabled(KEYED.withEnabled(false)));
    }

    @Test
    void publicRouteAllowsWithOrWithoutKey() {
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkApiKey(PUBLIC, null));
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkApiKey(PUBLIC, "anything"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void keyedRouteWithoutKeyIsUnauthorized(String key) {
        assertEquals(AccessDecision.API_KEY_MISSING, PolicyEvaluator.checkApiKey(KEYED, key));
    }

    @Test
    void keyedRouteChecksKey() {
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkApiKey(KEYED, "s3cret"));
        assertEquals(AccessDecision.API_KEY_INVALID, PolicyEvaluator.checkApiKey(KEYED, "s3cret "));
        assertEquals(AccessDecision.API_KEY_INVALID, PolicyEvaluator.checkApiKey(KEYED, "S3cret"));
        // the digest itself is not a valid key
        assertEquals(AccessDecision.API_KEY_INVALID, PolicyEvaluator.checkApiKey(KEYED, Sha256.hex("s3cret")));
    }

    @Test
    void individualChecks() {
        assertEquals(AccessDecision.ROUTE_NOT_FOUND, PolicyEvaluator.checkExists(null));
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkExists(PUBLIC));
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkEnabled(PUBLIC));
        assertEquals(AccessDecision.ROUTE_DISABLED, PolicyEvaluator.checkEnabled(PUBLIC.withEnabled(false)));
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkApiKey(PUBLIC, null));
        assertEquals(AccessDecision.ALLOW, PolicyEvaluator.checkApiKey(KEYED, "s3cret"));
        assertEquals(AccessDecision.API_KEY_INVALID, PolicyEvaluator.checkApiKey(KEYED, "x"));
        assertEquals(AccessDecision.API_KEY_MISSING, PolicyEvaluator.checkApiKey(KEYED, ""));
        // key check applies even to a disabled route when called on its own
        assertEquals(AccessDecision.API_KEY_INVALID, PolicyEvaluator.checkApiKey(KEYED.withEnabled(false), "x"));
    }

    @Test
    void decisionsExposeStatusAndReason() {
        assertEquals(200, AccessDecision.ALLOW.httpStatus());
        assertEquals(404, AccessDecision.ROUTE_NOT_FOUND.httpStatus());
        assertEquals(503, AccessDecision.ROUTE_DISABLED.httpStatus());
        assertEquals(401, AccessDecision.API_KEY_MISSING.httpStatus());
        assertEquals(403, AccessDecision.API_KEY_INVALID.httpStatus());
        assertEquals(429, AccessDecision.RATE_LIMITED.httpStatus());
        assertEquals(502, AccessDecision.FORWARD_FAILED.httpStatus());
        assertEquals("Rate limit exceeded", AccessDecision.RATE_LIMITED.reason());
        assertTrue(AccessDecision.ALLOW.isAllowed());
        for (AccessDecision d : EnumSet.complementOf(EnumSet.of(AccessDecision.ALLOW))) {
            assertFalse(d.isAllowed(), d.name());
        }
    }
}
