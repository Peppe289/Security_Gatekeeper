package io.github.peppe289.security_gatekeeper.route;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Generates high-entropy API keys (256 bits from {@link SecureRandom}). Keys
 * are shown to the admin once; only their SHA-256 digest is stored.
 */
@Component
public class ApiKeyGenerator {

    static final String KEY_PREFIX = "gk_";
    private static final int KEY_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    public String generate() {
        byte[] bytes = new byte[KEY_BYTES];
        random.nextBytes(bytes);
        return KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
