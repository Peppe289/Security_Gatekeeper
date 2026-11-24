package io.github.peppe289.security_gatekeeper.route;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.core.crypto.Sha256;
import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.ratelimit.RateLimiterService;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.InvalidRouteException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteAlreadyExistsException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteNotFoundException;
import io.github.peppe289.security_gatekeeper.support.TestProperties;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DuplicateKeyException;

/** Route management against a mocked repository: no database involved. */
@ExtendWith(MockitoExtension.class)
class RouteServiceTest {

    private static final String KEY = "gk_generated-key";
    private static final String TARGET = "http://upstream:8080";

    @Mock
    private RouteRepository repository;
    @Mock
    private ApiKeyGenerator keyGenerator;
    @Mock
    private RateLimiterService rateLimiter;
    @Captor
    private ArgumentCaptor<RoutePolicy> inserted;

    private RouteService service;

    @BeforeEach
    void setUp() {
        service = new RouteService(repository, keyGenerator, rateLimiter, TestProperties.defaults());
    }

    private static RoutePolicy policy(String prefix, boolean enabled, String keyHash) {
        return new RoutePolicy(prefix, TARGET, enabled, keyHash, 10, 5);
    }

    private static RouteDefinition definition(String prefix, boolean requireApiKey, Long burst, Long refill) {
        return new RouteDefinition(prefix, TARGET, true, requireApiKey, burst, refill);
    }

    @Nested
    class Create {

        @Test
        void storesOnlyTheHashAndReturnsTheKeyOnce() {
            when(keyGenerator.generate()).thenReturn(KEY);
            when(repository.findAll()).thenReturn(List.of(policy("svc", true, Sha256.hex(KEY))));

            RouteService.CreatedRoute created = service.create(definition("svc", true, 10L, 5L));

            verify(repository).insert(inserted.capture());
            assertEquals(Sha256.hex(KEY), inserted.getValue().getApiKeyHash());
            assertEquals(KEY, created.apiKey());
            assertTrue(service.find("svc").isPresent());
        }

        @Test
        void publicRouteGetsNoKey() {
            RouteService.CreatedRoute created = service.create(definition("svc", false, 10L, 5L));

            verify(repository).insert(inserted.capture());
            assertNull(inserted.getValue().getApiKeyHash());
            assertNull(created.apiKey());
            verifyNoInteractions(keyGenerator);
        }

        @Test
        void explicitRateParametersAreKept() {
            service.create(definition("svc", false, 7L, 3L));

            verify(repository).insert(inserted.capture());
            assertEquals(7, inserted.getValue().getBurstCapacity());
            assertEquals(3, inserted.getValue().getRefillPerSecond());
        }

        @Test
        void missingRateParametersFallBackToTheConfiguredDefaults() {
            service.create(definition("svc", false, null, null));

            verify(repository).insert(inserted.capture());
            assertEquals(TestProperties.DEFAULT_BURST, inserted.getValue().getBurstCapacity());
            assertEquals(TestProperties.DEFAULT_REFILL, inserted.getValue().getRefillPerSecond());
        }

        @Test
        void clearsLeftoverBucketsOfAnOlderRouteWithTheSamePrefixThenReloads() {
            service.create(definition("svc", false, 10L, 5L));

            InOrder order = inOrder(repository, rateLimiter);
            order.verify(repository).insert(any());
            order.verify(rateLimiter).resetAll(RateLimiterService.routeKeyPrefix("svc"));
            order.verify(repository).findAll();
        }

        @Test
        void duplicatePrefixBecomesADomainError() {
            doThrow(new DuplicateKeyException("routes_pkey")).when(repository).insert(any());

            assertThrows(RouteAlreadyExistsException.class, () -> service.create(definition("svc", false, 10L, 5L)));
            verifyNoInteractions(rateLimiter);
            verify(repository, never()).findAll();
        }

        @Test
        void invalidDefinitionIsRejectedBeforeReachingTheDatabase() {
            RouteDefinition bad = new RouteDefinition("svc", "ftp://upstream", true, false, 10L, 5L);

            InvalidRouteException e = assertThrows(InvalidRouteException.class, () -> service.create(bad));

            assertFalse(e.getMessage().contains("ftp://upstream"), "messages must not echo user input");
            verifyNoInteractions(repository, rateLimiter);
        }
    }

    @Nested
    class Update {

        @Test
        void setEnabledWritesOneColumnAndReturnsTheStoredRoute() {
            RoutePolicy stored = policy("svc", false, null);
            when(repository.updateEnabled("svc", false)).thenReturn(true);
            when(repository.findAll()).thenReturn(List.of(stored));

            assertSame(stored, service.setEnabled("svc", false));
        }

        @Test
        void rotateApiKeyStoresTheHashOfTheNewKey() {
            when(keyGenerator.generate()).thenReturn(KEY);
            when(repository.updateApiKeyHash("svc", Sha256.hex(KEY))).thenReturn(true);
            when(repository.findAll()).thenReturn(List.of(policy("svc", true, Sha256.hex(KEY))));

            assertEquals(KEY, service.rotateApiKey("svc"));
        }

        @Test
        void removeApiKeyClearsTheHash() {
            when(repository.updateApiKeyHash("svc", null)).thenReturn(true);
            when(repository.findAll()).thenReturn(List.of(policy("svc", true, null)));

            assertFalse(service.removeApiKey("svc").requiresApiKey());
        }

        @Test
        void unknownRouteFailsButTheCacheIsStillRefreshed() {
            when(repository.updateEnabled("gone", true)).thenReturn(false);

            assertThrows(RouteNotFoundException.class, () -> service.setEnabled("gone", true));
            // A deletion made on another instance must disappear from this one too.
            verify(repository).findAll();
        }

        @Test
        void routeDeletedBetweenWriteAndReloadIsNotFound() {
            when(repository.updateApiKeyHash("svc", null)).thenReturn(true);
            when(repository.findAll()).thenReturn(List.of());

            assertThrows(RouteNotFoundException.class, () -> service.removeApiKey("svc"));
        }

        @Test
        void nullPrefixNeverReachesTheDatabase() {
            assertThrows(RouteNotFoundException.class, () -> service.setEnabled(null, true));
            verify(repository, never()).updateEnabled(any(), anyBoolean());
        }
    }

    @Nested
    class Delete {

        @Test
        void dropsTheRouteAndItsRateLimitBuckets() {
            when(repository.delete("svc")).thenReturn(true);

            service.delete("svc");

            verify(rateLimiter).resetAll(RateLimiterService.routeKeyPrefix("svc"));
            verify(repository).findAll();
        }

        @Test
        void unknownRouteFailsWithoutSideEffects() {
            when(repository.delete(anyString())).thenReturn(false);

            assertThrows(RouteNotFoundException.class, () -> service.delete("gone"));
            assertThrows(RouteNotFoundException.class, () -> service.delete(null));
            verify(repository, never()).delete(null);
            verifyNoInteractions(rateLimiter);
        }
    }

    @Nested
    class Startup {

        @Test
        void seedsMissingRoutesWithDefaultsThenLoadsTheCache() {
            GatewayProperties properties = TestProperties.withSeed(List.of(
                    new GatewayProperties.SeedRoute("whoami", "http://whoami:80", true, null, null)));
            RouteService seeded = new RouteService(repository, keyGenerator, rateLimiter, properties);
            RoutePolicy existing = policy("whoami", true, null);
            when(repository.insertIfAbsent(any())).thenReturn(false); // already present: left untouched
            when(repository.findAll()).thenReturn(List.of(existing));

            seeded.afterSingletonsInstantiated();

            verify(repository).insertIfAbsent(inserted.capture());
            assertEquals("whoami", inserted.getValue().getPrefix());
            assertEquals(TestProperties.DEFAULT_BURST, inserted.getValue().getBurstCapacity());
            assertNull(inserted.getValue().getApiKeyHash());
            assertSame(existing, seeded.find("whoami").orElseThrow());
        }

        @Test
        void findAllIsSortedByPrefixAndFindToleratesNull() {
            when(repository.findAll()).thenReturn(List.of(policy("zeta", true, null), policy("alpha", true, null)));
            service.refresh();

            assertEquals(List.of("alpha", "zeta"), service.findAll().stream().map(RoutePolicy::getPrefix).toList());
            assertTrue(service.find(null).isEmpty());
            assertTrue(service.find("missing").isEmpty());
        }
    }
}
