package io.github.peppe289.security_gatekeeper.config;

import io.github.peppe289.security_gatekeeper.gateway.ProxyEntryFilter;
import io.github.peppe289.security_gatekeeper.gateway.pipeline.GatewayPipeline;
import io.github.peppe289.security_gatekeeper.monitoring.InFlightRequests;
import io.github.peppe289.security_gatekeeper.monitoring.LoadMonitor;
import io.github.peppe289.security_gatekeeper.ratelimit.NanoClock;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import io.github.peppe289.security_gatekeeper.route.RouteService;
import java.net.http.HttpClient;
import java.time.Clock;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class AppConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    NanoClock nanoClock() {
        return NanoClock.system();
    }

    /**
     * Shared upstream client: HTTP/1.1 (no h2c upgrade surprises with plain
     * HTTP upstreams), redirects passed through to the client, default TLS
     * validation.
     */
    @Bean
    HttpClient upstreamHttpClient(GatewayProperties properties) {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(properties.forwarder().connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Runs the reverse proxy right after the Spring Security filter chain. */
    @Bean
    FilterRegistrationBean<ProxyEntryFilter> proxyEntryFilter(GatewayPipeline pipeline, InFlightRequests inFlight) {
        FilterRegistrationBean<ProxyEntryFilter> registration =
                new FilterRegistrationBean<>(new ProxyEntryFilter(pipeline, inFlight));
        registration.addUrlPatterns("/*");
        registration.setOrder(SecurityFilterProperties.DEFAULT_FILTER_ORDER + 1);
        registration.setName("proxyEntryFilter");
        return registration;
    }

    /** Periodic maintenance, with intervals taken from typed configuration. */
    @Bean
    SchedulingConfigurer gatewayMaintenance(GatewayProperties properties, RateLimiterService rateLimiter,
                                            RouteService routes, LoadMonitor loadMonitor) {
        return (ScheduledTaskRegistrar registrar) -> {
            registrar.addFixedDelayTask(rateLimiter::evictIdle, properties.rateLimit().evictionInterval());
            registrar.addFixedDelayTask(routes::refresh, properties.routes().refreshInterval());
            registrar.addFixedRateTask(loadMonitor::sample, properties.monitoring().sampleInterval());
        };
    }
}
