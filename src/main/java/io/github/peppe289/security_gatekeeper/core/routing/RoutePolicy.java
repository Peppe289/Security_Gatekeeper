package io.github.peppe289.security_gatekeeper.core.routing;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Immutable description of a proxied route: {@code /{prefix}/**} is
 * forwarded to {@code targetUrl}. Instances are immutable, so a policy can be
 * shared between threads without synchronization; a change to a route is
 * written to the database and picked up as a new instance.
 *
 * <p>The API key is never stored in clear: only its SHA-256 digest.
 */
public final class RoutePolicy {

    public static final int MAX_PREFIX_LENGTH = 63;
    /** Regular-expression form of {@link #isValidPrefix(String)}, for declarative validation. */
    public static final String PREFIX_PATTERN = "[a-z0-9][a-z0-9-]{0,62}";
    public static final long MAX_BURST_CAPACITY = 1_000_000L;
    public static final long MAX_REFILL_PER_SECOND = 1_000_000_000L;
    private static final /*@ spec_public @*/ long NANOS_PER_SECOND = 1_000_000_000L;

    private final /*@ spec_public @*/ String prefix;
    private final /*@ spec_public @*/ String targetUrl;
    private final /*@ spec_public @*/ boolean enabled;
    private final /*@ spec_public nullable @*/ String apiKeyHash;
    private final /*@ spec_public @*/ long burstCapacity;
    private final /*@ spec_public @*/ long refillPerSecond;

    //@ public invariant prefix != null && 1 <= prefix.length() && prefix.length() <= MAX_PREFIX_LENGTH;
    //@ public invariant targetUrl != null;
    //@ public invariant apiKeyHash == null || apiKeyHash.length() == Sha256.HEX_LENGTH;
    //@ public invariant 1 <= burstCapacity && burstCapacity <= MAX_BURST_CAPACITY;
    //@ public invariant 1 <= refillPerSecond && refillPerSecond <= MAX_REFILL_PER_SECOND;

    /**
     * @param prefix          route prefix, see {@link #isValidPrefix(String)}
     * @param targetUrl       upstream base URL, see {@link #isValidTargetUrl(String)}; a trailing slash is removed
     * @param enabled         whether traffic is accepted (feature toggle)
     * @param apiKeyHash      SHA-256 hex digest of the API key, or {@code null} if the route is public
     * @param burstCapacity   token-bucket capacity in {@code [1, MAX_BURST_CAPACITY]}
     * @param refillPerSecond tokens per second in {@code [1, MAX_REFILL_PER_SECOND]}
     * @throws IllegalArgumentException if any argument is invalid
     */
    /*@ public normal_behavior
      @   requires isValidPrefix(prefix) && isValidTargetUrl(targetUrl);
      @   requires apiKeyHash == null || Sha256.isHexDigest(apiKeyHash);
      @   requires 1 <= burstCapacity && burstCapacity <= MAX_BURST_CAPACITY;
      @   requires 1 <= refillPerSecond && refillPerSecond <= MAX_REFILL_PER_SECOND;
      @   ensures this.prefix == prefix && this.enabled == enabled && this.apiKeyHash == apiKeyHash;
      @   ensures this.burstCapacity == burstCapacity && this.refillPerSecond == refillPerSecond;
      @ also public exceptional_behavior
      @   requires !isValidPrefix(prefix) || !isValidTargetUrl(targetUrl)
      @         || (apiKeyHash != null && !Sha256.isHexDigest(apiKeyHash))
      @         || burstCapacity < 1 || burstCapacity > MAX_BURST_CAPACITY
      @         || refillPerSecond < 1 || refillPerSecond > MAX_REFILL_PER_SECOND;
      @   signals_only IllegalArgumentException;
      @*/
    public RoutePolicy(/*@ nullable @*/ String prefix, /*@ nullable @*/ String targetUrl, boolean enabled, /*@ nullable @*/ String apiKeyHash,
                       long burstCapacity, long refillPerSecond) {
        validate(prefix, targetUrl, apiKeyHash, burstCapacity, refillPerSecond);
        this.prefix = prefix;
        this.targetUrl = stripTrailingSlash(targetUrl);
        this.enabled = enabled;
        this.apiKeyHash = apiKeyHash;
        this.burstCapacity = burstCapacity;
        this.refillPerSecond = refillPerSecond;
    }

    /*@ private normal_behavior
      @   requires isValidPrefix(prefix) && isValidTargetUrl(targetUrl);
      @   requires apiKeyHash == null || Sha256.isHexDigest(apiKeyHash);
      @   requires 1 <= burstCapacity && burstCapacity <= MAX_BURST_CAPACITY;
      @   requires 1 <= refillPerSecond && refillPerSecond <= MAX_REFILL_PER_SECOND;
      @ also private exceptional_behavior
      @   requires !isValidPrefix(prefix) || !isValidTargetUrl(targetUrl)
      @         || (apiKeyHash != null && !Sha256.isHexDigest(apiKeyHash))
      @         || burstCapacity < 1 || burstCapacity > MAX_BURST_CAPACITY
      @         || refillPerSecond < 1 || refillPerSecond > MAX_REFILL_PER_SECOND;
      @   signals_only IllegalArgumentException;
      @ pure
      @*/
    // The prover cannot relate several consecutive calls to methods it only knows by their
    // specification (isValidTargetUrl, Sha256.isHexDigest) to the same calls in this spec.
    // The body is a literal transcription of the spec; each check is verified on its own
    // and every rejection is covered by RoutePolicyTest.
    //@ skipesc
    private static void validate(/*@ nullable @*/ String prefix, /*@ nullable @*/ String targetUrl,
                                 /*@ nullable @*/ String apiKeyHash, long burstCapacity, long refillPerSecond) {
        if (!isValidPrefix(prefix)) {
            throw new IllegalArgumentException("prefix must match [a-z0-9][a-z0-9-]{0,62}");
        }
        if (!isValidTargetUrl(targetUrl)) {
            throw new IllegalArgumentException("targetUrl must be an absolute http(s) URL without credentials, query or fragment");
        }
        if (apiKeyHash != null && !Sha256.isHexDigest(apiKeyHash)) {
            throw new IllegalArgumentException("apiKeyHash must be a SHA-256 hex digest");
        }
        if (burstCapacity < 1 || burstCapacity > MAX_BURST_CAPACITY) {
            throw new IllegalArgumentException("burstCapacity must be in [1, 1000000]");
        }
        if (refillPerSecond < 1 || refillPerSecond > MAX_REFILL_PER_SECOND) {
            throw new IllegalArgumentException("refillPerSecond must be in [1, 1000000000]");
        }
    }

    /**
     * A prefix is 1..63 characters of {@code [a-z0-9-]} and does not start with {@code '-'}.
     * The restricted alphabet makes it safe in URLs, HTML and log lines.
     */
    /*@ public normal_behavior
      @   ensures \result ==> prefix != null && 1 <= prefix.length() && prefix.length() <= MAX_PREFIX_LENGTH;
      @ pure
      @*/
    public static boolean isValidPrefix(/*@ nullable @*/ String prefix) {
        if (prefix == null || prefix.isEmpty() || prefix.length() > MAX_PREFIX_LENGTH) {
            return false;
        }
        if (prefix.charAt(0) == '-') {
            return false;
        }
        //@ maintaining 0 <= i && i <= prefix.length();
        //@ decreasing prefix.length() - i;
        for (int i = 0; i < prefix.length(); i++) {
            char c = prefix.charAt(i);
            boolean lower = c >= 'a' && c <= 'z';
            boolean digit = c >= '0' && c <= '9';
            if (!lower && !digit && c != '-') {
                return false;
            }
        }
        return true;
    }

    /**
     * An upstream URL must be absolute {@code http}/{@code https}, have a host,
     * and carry no user-info, query or fragment.
     */
    /*@ public normal_behavior
      @   ensures \result ==> targetUrl != null && targetUrl.length() > 0;
      @ pure
      @*/
    //@ skipesc // body relies on java.net.URI, which has no usable JML specification; covered by RoutePolicyTest
    public static boolean isValidTargetUrl(/*@ nullable @*/ String targetUrl) {
        if (targetUrl == null) {
            return false;
        }
        try {
            URI uri = new URI(targetUrl);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            return (scheme.equals("http") || scheme.equals("https"))
                    && uri.getHost() != null
                    && uri.getRawUserInfo() == null
                    && uri.getRawQuery() == null
                    && uri.getRawFragment() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /*@ private normal_behavior
      @   requires url != null && url.length() > 0;
      @   ensures \result != null;
      @*/
    private static /*@ pure @*/ String stripTrailingSlash(String url) {
        int last = url.length() - 1;
        return url.charAt(last) == '/' ? url.substring(0, last) : url;
    }

    /** Nanoseconds between two tokens, always {@code >= 1}. */
    /*@ public normal_behavior
      @   ensures \result == NANOS_PER_SECOND / refillPerSecond;
      @   ensures \result >= 1;
      @ pure
      @*/
    public long nanosPerToken() {
        return NANOS_PER_SECOND / refillPerSecond;
    }

    /*@ public normal_behavior
      @   ensures \result == (apiKeyHash != null);
      @*/
    public /*@ pure @*/ boolean requiresApiKey() {
        return apiKeyHash != null;
    }

    /*@ public normal_behavior
      @   ensures \result == prefix;
      @*/
    public /*@ pure @*/ String getPrefix() {
        return prefix;
    }

    /*@ public normal_behavior
      @   ensures \result == targetUrl;
      @*/
    public /*@ pure @*/ String getTargetUrl() {
        return targetUrl;
    }

    /*@ public normal_behavior
      @   ensures \result == enabled;
      @*/
    public /*@ pure @*/ boolean isEnabled() {
        return enabled;
    }

    /*@ public normal_behavior
      @   ensures \result == apiKeyHash;
      @*/
    public /*@ pure nullable @*/ String getApiKeyHash() {
        return apiKeyHash;
    }

    /*@ public normal_behavior
      @   ensures \result == burstCapacity;
      @*/
    public /*@ pure @*/ long getBurstCapacity() {
        return burstCapacity;
    }

    /*@ public normal_behavior
      @   ensures \result == refillPerSecond;
      @*/
    public /*@ pure @*/ long getRefillPerSecond() {
        return refillPerSecond;
    }

    @Override
    //@ skipesc // diagnostic string only, no specification
    public String toString() {
        // The key digest is deliberately omitted.
        return "RoutePolicy[" + prefix + " -> " + targetUrl + ", enabled=" + enabled
                + ", apiKey=" + requiresApiKey() + ", burst=" + burstCapacity + ", refill/s=" + refillPerSecond + "]";
    }
}
