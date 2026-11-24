# Coverage report

## Coverage configuration

JaCoCo 0.8.16 (`jacoco-maven-plugin` in `pom.xml`), bound to `mvn verify`:

| Execution | Phase | What it does |
|---|---|---|
| `prepare-agent` | initialize | attaches the JaCoCo agent to the Surefire JVM (`@{argLine}`) |
| `report` | verify | HTML, XML and CSV reports in `target/site/jacoco/` |
| `check-core` | verify | gate on `core/**`: **95%** of lines and branches |
| `check-project` | verify | gate on the whole project: **85%** of lines, **80%** of branches |

Thresholds are Maven properties (`jacoco.core.*`, `jacoco.project.*`). The Spring Boot bootstrap
class and JMH-generated code are excluded: they carry no logic. The domain (`core`) gets a
stricter gate because it is pure Java and every path can be unit-tested; the Spring layers
also rely on integration tests. A gate set above the current figure fails the build
(checked: a 99% project gate fails with "lines covered ratio is 0.96").

In CI, the run summary shows both gates, and the XML report is uploaded to **Codecov**
(`codecov-action`, README badge). Codecov reports 94% instead of 96.8% because it counts a
line whose branches were only partly taken as a *partial*, not as covered.

## Coverage analysis

357 tests (unit + integration with Testcontainers):

| Scope | Lines | Branches |
|---|---|---|
| `core` (gate 95%) | 99.1% | 100% |
| Whole project (gate 85% / 80%) | **96.8%** (1,427 lines) | **92.6%** (598 branches) |
| Methods / instructions | 97.9% | 96.9% |

By package, branches are where the gaps are:

| Package | Lines | Branches |
|---|---|---|
| `admin` | 92.6% | **70.0%** (15 missed) |
| `gateway` (servlet entry point) | 95.6% | **78.6%** |
| `config` | 91.2% | 81.2% |
| `gateway.pipeline` | 97.9% | 83.3% |
| `route` | 97.9% | 86.1% |
| `monitoring` | 98.2% | 88.7% (12 missed) |
| `core.*`, `gateway.filter`, `gateway.forward`, `audit`, `ratelimit` | 95.6–100% | 95–100% |

**Lowest-covered classes**: `LoginController` (25% of branches: the "already logged in"
redirect is never exercised), `RouteForm` (82.6% lines, 50% branches: setters bound only by
the panel), `DashboardController` (89.2% / 57.1%: the `/_gatekeeper` redirect and some
form-error paths), `SecurityConfig` (the pre-encoded `{bcrypt}` password branch),
`JvmSystemProbe` (90.9% / 77.8%: platform-dependent branches, e.g. no `/proc/net/dev`).

**Methods never executed**: `DashboardController.root`, `RouteForm.setBurstCapacity` /
`setRefillPerSecond`, `RouteRepository.insertIfAbsent` (route seeding is unit-tested against a
mock, never against PostgreSQL), `AuditRepository.contains` (only reached after a sequence
collision), the `toString()` of two configuration records, and `Sha256`'s
`NoSuchAlgorithmException` handler, which is unreachable (every JVM must provide SHA-256).

## What coverage did, and did not, tell us

Coverage was used as **guidance**, not as a target (Weyuker: adequacy can only be judged
intuitively). It pointed at classes tested only indirectly: writing unit tests for them raised
`RateLimiterService` from 60.9% to 100% of lines, `AuditService` from 75.4% to 91.8% and
`HttpForwarder` from 78% to 100%. But full coverage did not mean strong tests: `NodeVerifier`
had every line executed (only 2 partial branches) while mutation testing found 18 surviving
mutants in it (see `mutation.md`). Coverage says the code ran, not that a test would notice it changing.

## Coverage improvement plan

1. **Admin panel branches** (largest gap): integration tests for the already-authenticated
   login redirect, the `/_gatekeeper` root redirect and the form validation errors of
   `RouteForm` (burst and refill out of range).
2. **Route seeding against PostgreSQL**: an integration test with
   `gateway.routes.seed[0]`, covering `RouteRepository.insertIfAbsent` and the "already
   present" case.
3. **Audit collision path on a real database**: two writers with the same `node-id`, to cover
   `AuditRepository.contains`.
4. **Platform-dependent monitoring**: inject the `/proc/net/dev` path in `JvmSystemProbe` so
   its fallback branches can be unit-tested.
5. Keep the unreachable `Sha256` handler and the `toString()` methods out of the target: they
   are not worth tests. Raise the project gate to 90% of lines once points 1–3 are done.
