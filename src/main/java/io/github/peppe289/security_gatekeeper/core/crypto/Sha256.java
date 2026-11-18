package io.github.peppe289.security_gatekeeper.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 helpers built only on the JDK. Used for the audit hash chain and for
 * storing API keys as digests instead of plaintext.
 */
public final class Sha256 {

    /** Length of a hex-encoded SHA-256 digest. */
    public static final int HEX_LENGTH = 64;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Sha256() {
    }

    /**
     * Hex-encoded SHA-256 of the UTF-8 bytes of {@code input}.
     *
     * @param input text to hash, not {@code null}
     * @return 64 lowercase hex characters
     */
    /*@ public normal_behavior
      @   requires input != null;
      @   ensures \result != null && \result.length() == HEX_LENGTH;
      @ pure
      @*/
    public static String hex(String input) {
        byte[] digest = newDigest().digest(input.getBytes(StandardCharsets.UTF_8));
        char[] out = new char[digest.length * 2];
        for (int i = 0; i < digest.length; i++) {
            int v = digest[i] & 0xFF;
            out[2 * i] = HEX[v >>> 4];
            out[2 * i + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * Compares two strings in time independent of where they first differ,
     * preventing timing side channels when checking secrets.
     *
     * @return {@code true} iff both are non-null and equal
     */
    /*@ public normal_behavior
      @   ensures (a == null || b == null) ==> !\result;
      @ pure
      @*/
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @return {@code true} iff {@code s} is exactly 64 lowercase hex characters
     */
    /*@ public normal_behavior
      @   ensures \result ==> s != null && s.length() == HEX_LENGTH;
      @ pure
      @*/
    public static boolean isHexDigest(String s) {
        if (s == null || s.length() != HEX_LENGTH) {
            return false;
        }
        //@ maintaining 0 <= i && i <= s.length();
        //@ decreasing s.length() - i;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean digit = c >= '0' && c <= '9';
            boolean lowerHex = c >= 'a' && c <= 'f';
            if (!digit && !lowerHex) {
                return false;
            }
        }
        return true;
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Every Java SE platform is required to support SHA-256.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
