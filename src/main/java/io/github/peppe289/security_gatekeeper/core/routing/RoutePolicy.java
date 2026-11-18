package io.github.peppe289.security_gatekeeper.core.routing;

import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Immutable description of a proxied route: {@code /{prefix}/**} is
 * forwarded to {@code targetUrl}. Changes produce new instances
 * ({@link #withEnabled(boolean)}, {@link #withApiKeyHash(String)}), so a policy
 * can be shared between threads without synchronization.
 *
 * <p>The API key is never stored in clear: only its SHA-256 digest.
 */
public final class RoutePolicy {

    public static final int MAX_PREFIX_LENGTH = 63;
    /** Regular-expression form of {@link #isValidPrefix(String)}, for declarative validation. */
    public static final String PREFIX_PATTERN = "[a-z0-9][a-z0-9-]{0,62}";
    public static final long MAX_BURST_CAPACITY = 1_000_000L;
    public static final long MAX_REFILL_PER_SECOND = 1_000_000_000L;
    private static final long NANOS_PER_SECOND = 1_000_000_000L;

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
    public RoutePolicy(String prefix, String targetUrl, boolean enabled, String apiKeyHash,
                       long burstCapacity, long refillPerSecond) {
        if (!isValidPrefix(prefix)) {
            throw new IllegalArgumentException("prefix must match " + PREFIX_PATTERN);
        }
        if (!isValidTargetUrl(targetUrl)) {
            throw new IllegalArgumentException("targetUrl must be an absolute http(s) URL without credentials, query or fragment");
        }
        if (apiKeyHash != null && !Sha256.isHexDigest(apiKeyHash)) {
            throw new IllegalArgumentException("apiKeyHash must be a SHA-256 hex digest");
        }
        if (burstCapacity < 1 || burstCapacity > MAX_BURST_CAPACITY) {
            throw new IllegalArgumentException("burstCapacity must be in [1, " + MAX_BURST_CAPACITY + "]");
        }
        if (refillPerSecond < 1 || refillPerSecond > MAX_REFILL_PER_SECOND) {
            throw new IllegalArgumentException("refillPerSecond must be in [1, " + MAX_REFILL_PER_SECOND + "]");
        }
        this.prefix = prefix;
        this.targetUrl = stripTrailingSlash(targetUrl);
        this.enabled = enabled;
        this.apiKeyHash = apiKeyHash;
        this.burstCapacity = burstCapacity;
        this.refillPerSecond = refillPerSecond;
    }

    /**
     * A prefix is 1..63 characters of {@code [a-z0-9-]} and does not start with {@code '-'}.
     * The restricted alphabet makes it safe in URLs, HTML and log lines.
     */
    /*@ public normal_behavior
      @   ensures \result ==> prefix != null && 1 <= prefix.length() && prefix.length() <= MAX_PREFIX_LENGTH;
      @ pure
      @*/
    public static boolean isValidPrefix(String prefix) {
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
      @   ensures \result ==> targetUrl != null;
      @ pure
      @*/
    public static boolean isValidTargetUrl(String targetUrl) {
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

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** @return a copy with the given enabled flag */
    /*@ public normal_behavior
      @   ensures \result.enabled == enabled && \result.prefix == prefix && \result.apiKeyHash == apiKeyHash;
      @*/
    public RoutePolicy withEnabled(boolean enabled) {
        return new RoutePolicy(prefix, targetUrl, enabled, apiKeyHash, burstCapacity, refillPerSecond);
    }

    /** @return a copy protected by the given key digest ({@code null} makes the route public) */
    /*@ public normal_behavior
      @   requires apiKeyHash == null || Sha256.isHexDigest(apiKeyHash);
      @   ensures \result.apiKeyHash == apiKeyHash && \result.prefix == prefix && \result.enabled == enabled;
      @*/
    public RoutePolicy withApiKeyHash(String apiKeyHash) {
        return new RoutePolicy(prefix, targetUrl, enabled, apiKeyHash, burstCapacity, refillPerSecond);
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

    //@ ensures \result == (apiKeyHash != null);
    public /*@ pure @*/ boolean requiresApiKey() {
        return apiKeyHash != null;
    }

    //@ ensures \result == prefix;
    public /*@ pure @*/ String getPrefix() {
        return prefix;
    }

    //@ ensures \result == targetUrl;
    public /*@ pure @*/ String getTargetUrl() {
        return targetUrl;
    }

    //@ ensures \result == enabled;
    public /*@ pure @*/ boolean isEnabled() {
        return enabled;
    }

    //@ ensures \result == apiKeyHash;
    public /*@ pure nullable @*/ String getApiKeyHash() {
        return apiKeyHash;
    }

    //@ ensures \result == burstCapacity;
    public /*@ pure @*/ long getBurstCapacity() {
        return burstCapacity;
    }

    //@ ensures \result == refillPerSecond;
    public /*@ pure @*/ long getRefillPerSecond() {
        return refillPerSecond;
    }

    @Override
    public String toString() {
        // The key digest is deliberately omitted.
        return "RoutePolicy[" + prefix + " -> " + targetUrl + ", enabled=" + enabled
                + ", apiKey=" + requiresApiKey() + ", burst=" + burstCapacity + ", refill/s=" + refillPerSecond + "]";
    }
}
