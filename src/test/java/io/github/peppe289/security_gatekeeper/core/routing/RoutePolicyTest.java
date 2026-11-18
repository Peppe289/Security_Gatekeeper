package io.github.peppe289.security_gatekeeper.core.routing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class RoutePolicyTest {

    private static final String URL = "http://orders:8080/api";
    private static final String HASH = Sha256.hex("key");

    private static RoutePolicy policy(String prefix, String url, String hash, long burst, long refill) {
        return new RoutePolicy(prefix, url, true, hash, burst, refill);
    }

    @Test
    void storesAllFields() {
        RoutePolicy p = new RoutePolicy("orders", URL, false, HASH, 7, 3);
        assertEquals("orders", p.getPrefix());
        assertEquals(URL, p.getTargetUrl());
        assertFalse(p.isEnabled());
        assertEquals(HASH, p.getApiKeyHash());
        assertTrue(p.requiresApiKey());
        assertEquals(7, p.getBurstCapacity());
        assertEquals(3, p.getRefillPerSecond());
    }

    @Test
    void publicRouteHasNoKey() {
        RoutePolicy p = policy("orders", URL, null, 1, 1);
        assertNull(p.getApiKeyHash());
        assertFalse(p.requiresApiKey());
    }

    @Test
    void trailingSlashIsRemovedFromTarget() {
        assertEquals("https://h", policy("a", "https://h/", null, 1, 1).getTargetUrl());
        assertEquals("https://h/x", policy("a", "https://h/x/", null, 1, 1).getTargetUrl());
        assertEquals("https://h/x", policy("a", "https://h/x", null, 1, 1).getTargetUrl());
    }

    @Test
    void nanosPerTokenIsInverseOfRate() {
        assertEquals(1_000_000_000L, policy("a", URL, null, 1, 1).nanosPerToken());
        assertEquals(100_000_000L, policy("a", URL, null, 1, 10).nanosPerToken());
        assertEquals(1L, policy("a", URL, null, 1, RoutePolicy.MAX_REFILL_PER_SECOND).nanosPerToken());
    }

    @Test
    void withersReturnModifiedCopies() {
        RoutePolicy p = policy("orders", URL, null, 5, 2);
        RoutePolicy disabled = p.withEnabled(false);
        assertNotSame(p, disabled);
        assertTrue(p.isEnabled());
        assertFalse(disabled.isEnabled());
        assertEquals(5, disabled.getBurstCapacity());
        assertEquals(2, disabled.getRefillPerSecond());
        assertEquals(URL, disabled.getTargetUrl());

        RoutePolicy keyed = disabled.withApiKeyHash(HASH);
        assertEquals(HASH, keyed.getApiKeyHash());
        assertFalse(keyed.isEnabled());
        assertEquals("orders", keyed.getPrefix());
        assertNull(keyed.withApiKeyHash(null).getApiKeyHash());
        assertTrue(keyed.withEnabled(true).isEnabled());
    }

    @Test
    void toStringNeverLeaksKeyDigest() {
        String s = policy("orders", URL, HASH, 5, 2).toString();
        assertFalse(s.contains(HASH));
        assertTrue(s.contains("orders"));
        assertTrue(s.contains("apiKey=true"));
    }

    @Test
    void boundariesOfRateParameters() {
        assertEquals(RoutePolicy.MAX_BURST_CAPACITY,
                policy("a", URL, null, RoutePolicy.MAX_BURST_CAPACITY, 1).getBurstCapacity());
        assertThrows(IllegalArgumentException.class, () -> policy("a", URL, null, 0, 1));
        assertThrows(IllegalArgumentException.class,
                () -> policy("a", URL, null, RoutePolicy.MAX_BURST_CAPACITY + 1, 1));
        assertThrows(IllegalArgumentException.class, () -> policy("a", URL, null, 1, 0));
        assertThrows(IllegalArgumentException.class,
                () -> policy("a", URL, null, 1, RoutePolicy.MAX_REFILL_PER_SECOND + 1));
    }

    @Test
    void rejectsInvalidArguments() {
        assertThrows(IllegalArgumentException.class, () -> policy("Bad", URL, null, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> policy("a", "ftp://h", null, 1, 1));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> policy("a", URL, "not-a-digest", 1, 1));
        assertEquals("apiKeyHash must be a SHA-256 hex digest", e.getMessage());

        RoutePolicy valid = policy("a", URL, null, 1, 1);
        e = assertThrows(IllegalArgumentException.class, () -> valid.withApiKeyHash("not-a-digest"));
        assertEquals("apiKeyHash must be a SHA-256 hex digest", e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "0", "orders", "orders-v2", "a-", "z9", "abcdefghijklmnopqrstuvwxyz0123456789-abcdefghijklmnopqrstuvwxyz"})
    void validPrefixes(String prefix) {
        assertTrue(RoutePolicy.isValidPrefix(prefix), prefix);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"-a", "A", "orders/v1", "or ders", "ord.ers", "ordérs", "a_b", "`", "{", "/", ":",
            "abcdefghijklmnopqrstuvwxyz0123456789-abcdefghijklmnopqrstuvwxyz0"})
    void invalidPrefixes(String prefix) {
        assertFalse(RoutePolicy.isValidPrefix(prefix), String.valueOf(prefix));
    }

    @Test
    void prefixLengthBoundary() {
        assertTrue(RoutePolicy.isValidPrefix("a".repeat(RoutePolicy.MAX_PREFIX_LENGTH)));
        assertFalse(RoutePolicy.isValidPrefix("a".repeat(RoutePolicy.MAX_PREFIX_LENGTH + 1)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://h", "https://h", "HTTP://h:81/base", "https://10.0.0.1:8443/a/b", "http://orders.svc.local"})
    void validTargets(String url) {
        assertTrue(RoutePolicy.isValidTargetUrl(url), url);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "orders:8080", "/relative", "ftp://h", "file:///etc/passwd", "http://",
            "http://user:pw@h", "http://h?x=1", "http://h#frag", "http://h:abc", "mailto:a@b"})
    void invalidTargets(String url) {
        assertFalse(RoutePolicy.isValidTargetUrl(url), String.valueOf(url));
    }
}
