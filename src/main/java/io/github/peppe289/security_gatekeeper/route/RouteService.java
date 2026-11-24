package io.github.peppe289.security_gatekeeper.route;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.InvalidRouteException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteAlreadyExistsException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteNotFoundException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

/**
 * Route management. The database is the source of truth; an immutable
 * in-memory snapshot serves the hot path (one volatile read per request, no
 * locking, no I/O).
 *
 * <p>Writes go to the database first and then refresh the snapshot. A periodic
 * {@link #refresh()} picks up changes made by other gateway instances.
 */
@Service
public class RouteService implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(RouteService.class);

    private final RouteRepository repository;
    private final ApiKeyGenerator keyGenerator;
    private final RateLimiterService rateLimiter;
    private final GatewayProperties.RateLimit defaults;
    private final List<GatewayProperties.SeedRoute> seed;

    private volatile Map<String, RoutePolicy> snapshot = Map.of();

    /** Result of a creation: the API key is returned exactly once, in clear. */
    public record CreatedRoute(RoutePolicy policy, String apiKey) {
    }

    public RouteService(RouteRepository repository, ApiKeyGenerator keyGenerator,
                        RateLimiterService rateLimiter, GatewayProperties properties) {
        this.repository = repository;
        this.keyGenerator = keyGenerator;
        this.rateLimiter = rateLimiter;
        this.defaults = properties.rateLimit();
        this.seed = properties.routes().seed();
    }

    /** Seeds configured routes (if absent) and loads the cache once the context is ready. */
    @Override
    public void afterSingletonsInstantiated() {
        for (GatewayProperties.SeedRoute s : seed) {
            RoutePolicy p = build(s.prefix(), s.targetUrl(), s.enabled(), null, s.burstCapacity(), s.refillPerSecond());
            if (repository.insertIfAbsent(p)) {
                log.info("Seeded route {}", p);
            }
        }
        refresh();
    }

    /**
     * Reloads all routes from the database. Synchronized so that a slow periodic refresh
     * cannot publish its older read over the snapshot taken right after an admin change.
     */
    public synchronized void refresh() {
        Map<String, RoutePolicy> fresh = new HashMap<>();
        for (RoutePolicy p : repository.findAll()) {
            fresh.put(p.getPrefix(), p);
        }
        snapshot = Map.copyOf(fresh);
    }

    public Optional<RoutePolicy> find(String prefix) {
        return prefix == null ? Optional.empty() : Optional.ofNullable(snapshot.get(prefix));
    }

    /** @return all routes sorted by prefix */
    public List<RoutePolicy> findAll() {
        return snapshot.values().stream().sorted(Comparator.comparing(RoutePolicy::getPrefix)).toList();
    }

    public CreatedRoute create(RouteDefinition def) {
        String apiKey = def.requireApiKey() ? keyGenerator.generate() : null;
        RoutePolicy policy = build(def.prefix(), def.targetUrl(), def.enabled(),
                apiKey == null ? null : Sha256.hex(apiKey), def.burstCapacity(), def.refillPerSecond());
        try {
            repository.insert(policy);
        } catch (DuplicateKeyException e) {
            throw new RouteAlreadyExistsException();
        }
        rateLimiter.resetAll(RateLimiterService.routeKeyPrefix(policy.getPrefix()));
        refresh();
        log.info("Route created: {}", policy);
        return new CreatedRoute(policy, apiKey);
    }

    public RoutePolicy setEnabled(String prefix, boolean enabled) {
        RoutePolicy updated = update(prefix, k -> repository.updateEnabled(k, enabled));
        log.info("Route {} {}", updated.getPrefix(), enabled ? "enabled" : "disabled");
        return updated;
    }

    /** Generates a new API key for the route, making it protected if it was public. */
    public String rotateApiKey(String prefix) {
        String apiKey = keyGenerator.generate();
        RoutePolicy updated = update(prefix, k -> repository.updateApiKeyHash(k, Sha256.hex(apiKey)));
        log.info("API key rotated for route {}", updated.getPrefix());
        return apiKey;
    }

    /** Makes the route public again. */
    public RoutePolicy removeApiKey(String prefix) {
        RoutePolicy updated = update(prefix, k -> repository.updateApiKeyHash(k, null));
        log.info("API key removed from route {}", updated.getPrefix());
        return updated;
    }

    public void delete(String prefix) {
        // Validated first: the prefix comes from the URL and is written to the log below.
        if (!RoutePolicy.isValidPrefix(prefix) || !repository.delete(prefix)) {
            throw new RouteNotFoundException();
        }
        rateLimiter.resetAll(RateLimiterService.routeKeyPrefix(prefix));
        refresh();
        log.info("Route deleted: {}", prefix);
    }

    /** Applies {@code write} to the database row, then returns the route as now stored. */
    private RoutePolicy update(String prefix, Predicate<String> write) {
        boolean updated = RoutePolicy.isValidPrefix(prefix) && write.test(prefix);
        refresh(); // also picks up a deletion made meanwhile (possibly by another instance)
        if (!updated) {
            throw new RouteNotFoundException();
        }
        return find(prefix).orElseThrow(RouteNotFoundException::new);
    }

    private RoutePolicy build(String prefix, String targetUrl, boolean enabled, String keyHash,
                              Long burstCapacity, Long refillPerSecond) {
        long burst = burstCapacity == null ? defaults.defaultBurstCapacity() : burstCapacity;
        long refill = refillPerSecond == null ? defaults.defaultRefillPerSecond() : refillPerSecond;
        try {
            return new RoutePolicy(prefix, targetUrl, enabled, keyHash, burst, refill);
        } catch (IllegalArgumentException e) {
            // core messages are constant strings: safe to show
            throw new InvalidRouteException(e.getMessage(), e);
        }
    }
}
