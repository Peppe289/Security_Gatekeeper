package io.github.peppe289.security_gatekeeper.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 helpers built only on the JDK. Used for the audit hash chain and for
 * storing API keys as digests instead of plaintext.
 */
public final class Sha256 {

    /** Length of a hex-encoded SHA-256 digest. */
    public static final int HEX_LENGTH = 64;

    private static final HexFormat HEX = HexFormat.of();

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
    //@ skipesc // body relies on MessageDigest and HexFormat, which have no usable JML specification; covered by Sha256Test
    public static String hex(String input) {
        return HEX.formatHex(newDigest().digest(input.getBytes(StandardCharsets.UTF_8)));
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
    public static boolean constantTimeEquals(/*@ nullable @*/ String a, /*@ nullable @*/ String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @return {@code true} iff {@code s} is exactly 64 lowercase hex characters
     */
    /*@ public normal_behavior
      @   ensures \result <==> s != null && s.length() == HEX_LENGTH
      @       && (\forall int j; 0 <= j && j < HEX_LENGTH;
      @              ('0' <= s.charAt(j) && s.charAt(j) <= '9') || ('a' <= s.charAt(j) && s.charAt(j) <= 'f'));
      @ pure
      @*/
    public static boolean isHexDigest(/*@ nullable @*/ String s) {
        if (s == null || s.length() != HEX_LENGTH) {
            return false;
        }
        //@ maintaining 0 <= i && i <= s.length();
        //@ maintaining (\forall int j; 0 <= j && j < i;
        //@     ('0' <= s.charAt(j) && s.charAt(j) <= '9') || ('a' <= s.charAt(j) && s.charAt(j) <= 'f'));
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
