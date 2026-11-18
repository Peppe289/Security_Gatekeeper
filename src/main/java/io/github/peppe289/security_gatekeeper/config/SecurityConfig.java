package io.github.peppe289.security_gatekeeper.config;

import static io.github.peppe289.security_gatekeeper.gateway.ProxyEntryFilter.ADMIN_PATH;

import io.github.peppe289.security_gatekeeper.admin.LoginThrottle;
import java.security.SecureRandom;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

/**
 * Two independent security chains:
 * <ol>
 *   <li><b>Admin</b> ({@code /_gatekeeper/**}): form login, session, CSRF,
 *       strict CSP and security headers, login brute-force throttling.</li>
 *   <li><b>Proxy</b> (everything else): no gateway authentication (routes are
 *       protected by the gateway pipeline: API keys, rate limits), no session,
 *       no header rewriting — the upstream controls its own headers.</li>
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    static final String LOGIN_PATH = ADMIN_PATH + "/login";

    private static final String CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self'; style-src 'self'; "
            + "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            + "form-action 'self'; frame-ancestors 'none'";

    @Bean
    @Order(1)
    SecurityFilterChain adminChain(HttpSecurity http, LoginThrottle loginThrottle) throws Exception {
        http.securityMatcher(ADMIN_PATH, ADMIN_PATH + "/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(LOGIN_PATH, ADMIN_PATH + "/assets/**", ADMIN_PATH + "/health",
                                ADMIN_PATH + "/health/**", ADMIN_PATH + "/error").permitAll()
                        .anyRequest().hasRole("ADMIN"))
                .formLogin(form -> form
                        .loginPage(LOGIN_PATH)
                        .defaultSuccessUrl(ADMIN_PATH + "/", true)
                        .failureUrl(LOGIN_PATH + "?error"))
                .logout(logout -> logout
                        .logoutUrl(ADMIN_PATH + "/logout")
                        .logoutSuccessUrl(LOGIN_PATH + "?logout"))
                .sessionManagement(session -> session.maximumSessions(1))
                .addFilterBefore(loginThrottle.filter(LOGIN_PATH), UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                        .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN))
                        .frameOptions(frame -> frame.deny())
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=()")));
        return http.build();
    }

    /**
     * Proxied traffic. CSRF protection is disabled on purpose: the gateway uses
     * no cookie-based authentication here (its session cookie is stripped before
     * forwarding and is scoped to the admin path), so there is no ambient
     * credential a cross-site request could abuse.
     */
    @Bean
    @Order(2)
    SecurityFilterChain proxyChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .securityContext(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .headers(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Publishes authentication success/failure events (used by {@link LoginThrottle}). */
    @Bean
    AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    UserDetailsService adminUser(GatewayProperties properties, PasswordEncoder encoder) {
        String password = properties.admin().password();
        if (password == null || password.isBlank()) {
            byte[] random = new byte[18];
            new SecureRandom().nextBytes(random);
            password = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            log.warn("\n\n  No GATEWAY_ADMIN_PASSWORD set. Generated admin password: {}\n"
                    + "  It changes at every restart: set GATEWAY_ADMIN_PASSWORD for a stable one.\n", password);
        }
        String encoded = password.startsWith("{") ? password : encoder.encode(password);
        return new InMemoryUserDetailsManager(User.withUsername(properties.admin().username())
                .password(encoded)
                .roles("ADMIN")
                .build());
    }
}
