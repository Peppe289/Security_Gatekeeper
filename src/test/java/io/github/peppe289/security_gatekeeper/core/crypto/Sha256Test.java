package io.github.peppe289.security_gatekeeper.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class Sha256Test {

    @Test
    void hexMatchesKnownVectors() {
        // FIPS 180-2 test vectors
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Sha256.hex(""));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Sha256.hex("abc"));
    }

    @Test
    void hexEncodesUtf8() {
        assertEquals(Sha256.HEX_LENGTH, Sha256.hex("café").length());
        assertFalse(Sha256.hex("café").equals(Sha256.hex("cafe")));
        assertTrue(Sha256.isHexDigest(Sha256.hex("café")));
    }

    @Test
    void constantTimeEqualsComparesContent() {
        assertTrue(Sha256.constantTimeEquals("secret", new String("secret")));
        assertFalse(Sha256.constantTimeEquals("secret", "secreT"));
        assertFalse(Sha256.constantTimeEquals("secret", "secret1"));
        assertTrue(Sha256.constantTimeEquals("", ""));
    }

    @Test
    void constantTimeEqualsRejectsNulls() {
        assertFalse(Sha256.constantTimeEquals(null, "a"));
        assertFalse(Sha256.constantTimeEquals("a", null));
        assertFalse(Sha256.constantTimeEquals(null, null));
    }

    @Test
    void isHexDigestAcceptsDigests() {
        assertTrue(Sha256.isHexDigest(Sha256.hex("x")));
        assertTrue(Sha256.isHexDigest("0123456789abcdef".repeat(4)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",   // 63 chars
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65 chars
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",  // uppercase
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  // 'g' (> 'f')
            "/123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  // '/' (< '0')
            ":123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  // ':' (> '9')
            "`123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  // '`' (< 'a')
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"   // last char invalid
    })
    void isHexDigestRejectsEverythingElse(String s) {
        assertFalse(Sha256.isHexDigest(s));
    }
}
