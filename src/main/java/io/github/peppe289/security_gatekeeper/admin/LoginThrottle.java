package io.github.peppe289.security_gatekeeper.admin;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Brute-force protection for the admin login, built on the same token buckets
 * as the proxy: every failed login from an IP consumes a token; when the
 * bucket is empty, login attempts from that IP are redirected to
 * {@code login?blocked} until it refills. A successful login resets the bucket.
 */
@Component
public class LoginThrottle {

    private static final Logger log = LoggerFactory.getLogger(LoginThrottle.class);
    private static final String KEY_PREFIX = "login|";

    private final RateLimiterService rateLimiter;
    private final long maxFailures;
    private final long nanosPerAttempt;

    public LoginThrottle(RateLimiterService rateLimiter, GatewayProperties properties) {
        this.rateLimiter = rateLimiter;
        this.maxFailures = properties.loginThrottle().maxFailures();
        this.nanosPerAttempt = Math.max(1, properties.loginThrottle().recovery().toNanos());
    }

    public boolean isBlocked(String clientIp) {
        return rateLimiter.isExhausted(KEY_PREFIX + clientIp);
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        String ip = clientIp(event.getAuthentication().getDetails());
        if (ip != null) {
            rateLimiter.tryAcquire(KEY_PREFIX + ip, maxFailures, nanosPerAttempt);
            log.warn("Failed admin login from {}", ip);
        }
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String ip = clientIp(event.getAuthentication().getDetails());
        if (ip != null) {
            rateLimiter.reset(KEY_PREFIX + ip);
        }
    }

    private static String clientIp(Object details) {
        return details instanceof WebAuthenticationDetails web ? web.getRemoteAddress() : null;
    }

    /** Servlet filter placed before the login processing filter. Not a bean: added to the security chain only. */
    public OncePerRequestFilter filter(String loginProcessingPath) {
        return new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilter(HttpServletRequest request) {
                return !"POST".equals(request.getMethod())
                        || !request.getRequestURI().equals(request.getContextPath() + loginProcessingPath);
            }

            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                if (isBlocked(request.getRemoteAddr())) {
                    response.sendRedirect(request.getContextPath() + loginProcessingPath + "?blocked");
                    return;
                }
                chain.doFilter(request, response);
            }
        };
    }
}
