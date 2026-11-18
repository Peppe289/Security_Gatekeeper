package io.github.peppe289.security_gatekeeper.audit;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.audit.AuditRecord;
import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * HMAC-SHA256 keys that authenticate the audit trail.
 *
 * <p>The hash chain alone uses no secret: anyone able to write to the database
 * could rewrite a record and recompute every following hash. Each record is
 * therefore also signed with {@code HMAC(key, nodeId | hash)}; since the hash
 * covers the record content and the link to its predecessor, the chain cannot
 * be rewritten without the key, which never leaves the configuration.
 *
 * <p>New records and anchors are signed with the active key. Retired keys are
 * kept for verification only. A key is identified by a short fingerprint
 * ({@link #keyId(String)}), stored next to each signature.
 */
@Component
public class AuditKeys {

    static final int MIN_KEY_LENGTH = 32;
    private static final String ALGORITHM = "HmacSHA256";
    private static final String RECORD_DOMAIN = "gatekeeper-audit-record-v1|";
    private static final HexFormat HEX = HexFormat.of();

    private final String activeKeyId;
    // Mac instances are not thread-safe: the writer signs while an admin may be verifying.
    private final Map<String, ThreadLocal<Mac>> macs;

    /** A signature and the fingerprint of the key that produced it. */
    public record Signature(String keyId, String mac) {
    }

    @Autowired
    public AuditKeys(GatewayProperties properties) {
        this(properties.audit().hmacKey(), properties.audit().previousHmacKeys());
    }

    AuditKeys(String activeKey, List<String> previousKeys) {
        List<String> all = new ArrayList<>();
        all.add(activeKey);
        all.addAll(previousKeys);
        Map<String, ThreadLocal<Mac>> byId = new LinkedHashMap<>();
        for (String key : all) {
            if (key == null || key.length() < MIN_KEY_LENGTH) {
                throw new IllegalArgumentException("audit HMAC keys must be at least " + MIN_KEY_LENGTH + " characters");
            }
            byte[] secret = key.getBytes(StandardCharsets.UTF_8);
            byId.putIfAbsent(keyId(key), ThreadLocal.withInitial(() -> newMac(secret)));
        }
        this.activeKeyId = keyId(activeKey);
        this.macs = Map.copyOf(byId);
    }

    /** Public, non-reversible fingerprint of a key (16 hex characters). */
    static String keyId(String key) {
        return Sha256.hex("gatekeeper-audit-key-id|" + key).substring(0, 16);
    }

    /** What is signed for a record: its node and its chain hash. */
    static String recordMessage(String nodeId, AuditRecord record) {
        return RECORD_DOMAIN + nodeId + "|" + record.getHash();
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    /** Signs {@code message} with the active key. */
    public Signature sign(String message) {
        return new Signature(activeKeyId, mac(activeKeyId, message));
    }

    /**
     * @return {@code true} iff {@code mac} is the signature of {@code message} by the key
     *         {@code keyId}; {@code false} if the key is unknown or an argument is {@code null}
     */
    public boolean verify(String keyId, String message, String mac) {
        if (keyId == null || mac == null || !macs.containsKey(keyId)) {
            return false;
        }
        return Sha256.constantTimeEquals(mac(keyId, message), mac);
    }

    private String mac(String keyId, String message) {
        return HEX.formatHex(macs.get(keyId).get().doFinal(message.getBytes(StandardCharsets.UTF_8)));
    }

    private static Mac newMac(byte[] secret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret, ALGORITHM));
            return mac;
        } catch (GeneralSecurityException e) {
            // Every Java SE platform is required to support HmacSHA256.
            throw new IllegalStateException(ALGORITHM + " not available", e);
        }
    }
}
