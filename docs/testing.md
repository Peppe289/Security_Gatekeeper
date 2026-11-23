# Testing report

## Approach

**329 tests** (JUnit 6.1.3, Mockito 5.24.0), all passing, run by `./mvnw verify` locally and
in CI. They are organised by test level:

| Level | Tests | Time | Scope |
|---|---|---|---|
| Unit | 297 | ~4 s | one class in isolation; collaborators mocked or replaced by fakes |
| Integration | 32 | ~40 s | the whole application on a random port, with a real PostgreSQL started by Testcontainers |

The domain (`core`) has no framework and no I/O, so it is tested without mocks; the Spring
layers are tested with mocked dependencies. Integration tests cover what mocks cannot: SQL,
migrations, Spring Security, the servlet pipeline and the shutdown order.

## Critical components and their tests

| Component | Tests | What is verified |
|---|---|---|
| Token bucket (`core`) | 30 | refill, burst, no banking of idle time, clock going backwards, overflow-free arithmetic |
| Route policy and checks (`core`) | 55 | prefix/URL validation, 404/503/401/403 decisions, constant-time key comparison |
| Audit chain (`core`) | 21 | hash linking, canonical form, verifier detecting edits, gaps and reordering |
| `RateLimiterService` | 14 | per-client buckets, eviction, fail-closed limit on tracked clients |
| `AuditService`, keys, anchors, verifier | 37 | async writer, retries, sequence collisions, HMAC, anchors, tampering cases |
| Gateway filters and forwarding | 55 | pipeline order, short-circuits, header rewriting, 502/504/400 mapping |
| Admin (`LoginThrottle`, dashboard) | 15 | brute-force blocking and recovery, statistics cache, verification cooldown |
| Monitoring | 39 | load sampling, peaks, thresholds |
| Integration | 32 | end-to-end proxying, admin panel and CSRF, audit tampering, shutdown |

## Test design

Tests are derived both from the **specification** (black-box) and from the **code**
(white-box):

- **Equivalence partitioning**: one test per class of input. Examples: route checks
  (missing, disabled, no key, wrong key, valid key); a request body with a declared length,
  chunked, or neither.
- **Boundary values**: `LoadReportTest` checks the 50%, 70% and 90% thresholds exactly on
  the boundary and just below it (`0.6999`, `0.70`, …). `RateLimiterServiceTest` checks
  refill at `period − 1` and `period` nanoseconds, and the login throttle one failure short
  of the limit.
- **Branch coverage** guides the rest: JaCoCo shows 99.1% lines and 100% branches on
  `core`, 96.4% / 91.1% on the whole project. Coverage is an indicator, not the goal.
- `@ParameterizedTest` keeps boundary tables readable; `@Nested` groups tests by behaviour.

## Mocking strategy

Mockito replaces the JDK `HttpClient`, the repositories, the anchor store, and the audit
service and rate limiter seen from the filters. **Time** is the most important one. `TokenBucket` receives the current instant as a
parameter, and the services take a `Clock` or `NanoClock`, so tests drive time explicitly
instead of sleeping. This improves *controllability*. Mocked collaborators improve
*observability*: tests verify what was written, retried or never called.

## FIRST principles

- **Fast**: the 297 unit tests run in about 4 s. Integration tests share one cached Spring
  context and one database container.
- **Independent**: no shared mutable state. Each integration test creates its own route,
  and the shutdown test uses its own application context.
- **Repeatable**: no `Thread.sleep` in assertions. Fake clocks make time deterministic, and
  asynchronous effects are awaited with `verify(mock, timeout(...))` or by polling a
  condition. The async tests were run five times in a row with no failure.
- **Self-validating**: every test asserts its outcome; nothing needs manual inspection.
- **Thorough**: error paths are tested as much as the happy path: database down, queue
  full, sequence collisions, forged or missing signatures, truncated chains, spoofed
  `X-Forwarded-*` headers, cookies injected by an upstream.

## CI integration

`ci.yml` runs `./mvnw verify` on every push and pull request. Test results are published on
the run (`dorny/test-reporter`), and the JaCoCo gate (85% on `core`) fails the build if
coverage drops. Mutation testing with PiTest runs in a separate job (see
`mutation.md`).

## Defects found by tests

- **Audit events lost on shutdown.** `AuditShutdownIntegrationTest` stops the application
  while a request is still in flight. It showed that the audit writer stopped *before*
  Tomcat's graceful shutdown, so the events of the last requests were silently lost. Fixed
  by moving the writer's lifecycle phase below the web server's; a unit test now guards the
  phase.
- New unit tests raised line coverage of `RateLimiterService` from 60.9% to 100%,
  `AuditService` from 75.4% to 91.8%, `HttpForwarder` from 78.0% to 100%.

## Known warnings

None from the compiler or the tests. On JDK 26+ the JVM warns that Spring mutates a final
field reflectively (JEP 500): it comes from the framework.
