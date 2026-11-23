package io.github.peppe289.security_gatekeeper.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.filter.OncePerRequestFilter;

/** Brute-force protection of the admin login: {@value #MAX_FAILURES} failures, then one attempt per minute. */
class LoginThrottleTest {

    private static final long MAX_FAILURES = 3;
    private static final Duration RECOVERY = Duration.ofMinutes(1);
    private static final String LOGIN = "/_gatekeeper/login";
    private static final String ATTACKER = "203.0.113.9";
    private static final String OTHER = "198.51.100.4";

    private final AtomicLong now = new AtomicLong();
    private LoginThrottle throttle;

    @BeforeEach
    void setUp() {
        GatewayProperties properties = TestProperties.with(new GatewayProperties.LoginThrottle(MAX_FAILURES, RECOVERY));
        throttle = new LoginThrottle(now::get, properties);
    }

    private static UsernamePasswordAuthenticationToken attempt(String ip) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("admin", "wrong");
        auth.setDetails(new WebAuthenticationDetails(ip, null));
        return auth;
    }

    private void fail(String ip, long times) {
        for (int i = 0; i < times; i++) {
            throttle.onFailure(new AuthenticationFailureBadCredentialsEvent(attempt(ip), new BadCredentialsException("x")));
        }
    }

    @Nested
    class Blocking {

        @Test
        void unknownClientIsNotBlocked() {
            assertFalse(throttle.isBlocked(ATTACKER));
        }

        @Test
        void oneFailureShortOfTheLimitIsNotBlocked() {
            fail(ATTACKER, MAX_FAILURES - 1);
            assertFalse(throttle.isBlocked(ATTACKER));
        }

        @Test
        void reachingTheLimitBlocksOnlyThatClient() {
            fail(ATTACKER, MAX_FAILURES);

            assertTrue(throttle.isBlocked(ATTACKER));
            assertFalse(throttle.isBlocked(OTHER));
        }

        @Test
        void oneAttemptIsAllowedAgainAfterTheRecoveryPeriod() {
            fail(ATTACKER, MAX_FAILURES);

            now.addAndGet(RECOVERY.toNanos() - 1);
            assertTrue(throttle.isBlocked(ATTACKER));
            now.addAndGet(1);
            assertFalse(throttle.isBlocked(ATTACKER));

            fail(ATTACKER, 1);
            assertTrue(throttle.isBlocked(ATTACKER), "a single recovered attempt, not a new burst");
        }

        @Test
        void successfulLoginClearsTheFailures() {
            fail(ATTACKER, MAX_FAILURES);

            throttle.onSuccess(new AuthenticationSuccessEvent(attempt(ATTACKER)));

            assertFalse(throttle.isBlocked(ATTACKER));
        }

        @Test
        void eventsWithoutWebDetailsAreIgnored() {
            UsernamePasswordAuthenticationToken noDetails = new UsernamePasswordAuthenticationToken("admin", "x");
            for (int i = 0; i < MAX_FAILURES; i++) {
                throttle.onFailure(new AuthenticationFailureBadCredentialsEvent(noDetails, new BadCredentialsException("x")));
            }
            throttle.onSuccess(new AuthenticationSuccessEvent(noDetails));

            assertFalse(throttle.isBlocked(ATTACKER));
        }
    }

    @Nested
    class Filter {

        private OncePerRequestFilter filter;
        private MockHttpServletResponse response;

        @BeforeEach
        void createFilter() {
            filter = throttle.filter(LOGIN);
        }

        private MockFilterChain run(String method, String uri, String ip) throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
            request.setRemoteAddr(ip);
            MockFilterChain chain = new MockFilterChain();
            response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            return chain;
        }

        @Test
        void blockedClientPostingTheLoginIsRedirected() throws Exception {
            fail(ATTACKER, MAX_FAILURES);

            MockFilterChain chain = run("POST", LOGIN, ATTACKER);

            assertNull(chain.getRequest(), "the login must not be processed");
            assertEquals(LOGIN + "?blocked", response.getRedirectedUrl());
        }

        @Test
        void allowedClientReachesTheLogin() throws Exception {
            MockFilterChain chain = run("POST", LOGIN, ATTACKER);
            assertNotNull(chain.getRequest());
        }

        @Test
        void otherRequestsOfABlockedClientAreNotFiltered() throws Exception {
            fail(ATTACKER, MAX_FAILURES);

            assertNotNull(run("GET", LOGIN, ATTACKER).getRequest(), "the login page itself stays visible");
            assertNotNull(run("POST", "/_gatekeeper/routes", ATTACKER).getRequest());
        }
    }
}
