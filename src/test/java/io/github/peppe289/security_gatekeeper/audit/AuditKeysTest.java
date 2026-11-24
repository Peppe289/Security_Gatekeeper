package io.github.peppe289.security_gatekeeper.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class AuditKeysTest {

    static final String KEY = "unit-test-audit-key-0123456789abcdef";
    static final String OLD_KEY = "unit-test-retired-key-0123456789abcd";

    @Test
    void signatureVerifiesWithTheSameKey() {
        AuditKeys keys = new AuditKeys(KEY, List.of());
        AuditKeys.Signature s = keys.sign("message");
        assertEquals(keys.activeKeyId(), s.keyId());
        assertEquals(64, s.mac().length());
        assertTrue(keys.verify(s.keyId(), "message", s.mac()));
    }

    @Test
    void alteredMessageOrMacIsRejected() {
        AuditKeys keys = new AuditKeys(KEY, List.of());
        AuditKeys.Signature s = keys.sign("message");
        assertFalse(keys.verify(s.keyId(), "messagE", s.mac()));
        String flipped = (s.mac().charAt(0) == '0' ? "1" : "0") + s.mac().substring(1);
        assertFalse(keys.verify(s.keyId(), "message", flipped));
    }

    @Test
    void anotherKeyCannotForgeSignatures() {
        AuditKeys keys = new AuditKeys(KEY, List.of());
        AuditKeys attacker = new AuditKeys("attacker-key-that-is-long-enough-000", List.of());
        AuditKeys.Signature forged = attacker.sign("message");
        assertFalse(keys.verify(forged.keyId(), "message", forged.mac()), "unknown key id");
        assertFalse(keys.verify(keys.activeKeyId(), "message", forged.mac()), "claimed known key id");
    }

    @Test
    void retiredKeysStillVerifyButNoLongerSign() {
        AuditKeys before = new AuditKeys(OLD_KEY, List.of());
        AuditKeys.Signature old = before.sign("message");
        AuditKeys after = new AuditKeys(KEY, List.of(OLD_KEY));
        assertTrue(after.verify(old.keyId(), "message", old.mac()));
        assertNotEquals(old.keyId(), after.sign("message").keyId());
    }

    @Test
    void keyIdIsAStableFingerprint() {
        assertEquals(AuditKeys.keyId(KEY), AuditKeys.keyId(KEY));
        assertEquals(16, AuditKeys.keyId(KEY).length());
        assertNotEquals(AuditKeys.keyId(KEY), AuditKeys.keyId(OLD_KEY));
    }

    @Test
    void nullsAreRejected() {
        AuditKeys keys = new AuditKeys(KEY, List.of());
        AuditKeys.Signature s = keys.sign("message");
        assertFalse(keys.verify(null, "message", s.mac()));
        assertFalse(keys.verify(s.keyId(), "message", null));
    }

    @Test
    void shortKeysAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new AuditKeys("too-short", List.of()));
        assertThrows(IllegalArgumentException.class, () -> new AuditKeys(KEY, List.of("too-short")));
    }

    @Test
    void keyLengthBoundary() {
        String exactly32 = "k".repeat(AuditKeys.MIN_KEY_LENGTH);
        new AuditKeys(exactly32, List.of());
        assertThrows(IllegalArgumentException.class,
                () -> new AuditKeys(exactly32.substring(1), List.of()), "31 characters");
        assertThrows(IllegalArgumentException.class, () -> new AuditKeys(null, List.of()));
    }

    @Test
    void unknownKeyIdIsRejectedWithoutError() {
        AuditKeys keys = new AuditKeys(KEY, List.of());
        AuditKeys.Signature s = keys.sign("message");
        assertFalse(keys.verify("0000000000000000", "message", s.mac()));
    }
}
