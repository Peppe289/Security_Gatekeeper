# Mutation testing report

## Mutation testing configuration

PiTest 1.30.2 with `pitest-junit5-plugin` 1.2.3 (`pom.xml`):

| Setting | Value |
|---|---|
| Target classes / tests | `core.*` (token bucket, route policy, audit chain, SHA-256) |
| Excluded tests | `benchmark.*` (JMH) |
| Mutators | `STRONGER`: the defaults plus conditional removal |
| Quality gates | `mutationThreshold` **90%**, `coverageThreshold` **95%** (line coverage of mutated classes) |
| Output | HTML and XML in `target/pit-reports/`, not timestamped |

`./mvnw -Pmutation verify` binds the gate to `verify`. In CI a separate job runs it on every
push and pull request; the run summary lists every non-killed mutant, the report is an artifact, and the score
feeds the README badge. (The badge service of the lab example, `badge.pitest.org`, does not
resolve, so CI publishes a shields.io endpoint on a `badges` branch instead.)

A second profile, **`-Pmutation-all`**, mutates **the whole project** with the unit tests, for
analysis only (no threshold, report in `target/pit-reports-all/`). Integration tests are left
out: they would start PostgreSQL for every one of the ~1,000 mutants.

## Mutation analysis

**Gate (`core`)**: 260 mutants, **260 killed (100%)**, line coverage 97%. Too clean to learn
from, hence the whole-project campaign:

| Whole project | Before | After new tests |
|---|---|---|
| Mutants | 1,074 | 1,074 |
| Killed + timed out | 733 | 776 |
| Survived | 142 | **102** |
| No coverage | 199 | 196 |
| Mutation score | 68.2% | **72.3%** |
| Test strength (covered mutants only) | 83.8% | **88.4%** |

**No coverage (196)** sits in classes only integration tests reach: `AuditRepository`,
`ProxyEntryFilter`, `DashboardController`, `RouteRepository`, `SecurityConfig`, `AppConfig`.

### Patterns in the survivors

1. **Masking by layered checks.** `NodeVerifier` had 18 survivors despite every line being
   covered. Its checks are layered (hash chain, MAC present, MAC valid, anchor): removing one
   left the record rejected by the next, and tests asserting only `valid() == false` could not
   tell which defence fired. Asserting the *reason*, the *position* and `accept()`'s result,
   plus missing cases (record deleted in the middle, edited without the key, chain not starting
   from genesis), left **4 survivors, all equivalent**.
2. **Equivalent mutants** (slide 08: undecidable in general, found by reasoning):
   - `return fail(...)` replaced by `return false`: `fail` already returns `false`;
   - `Retry-After` arithmetic in `RateLimitFilter`: the domain (≥ 1 token/s) makes it 1 anyway;
   - PiTest removes the comparison but keeps the `compareAndSet` call in `RateLimiterService`,
     so the side effect is unchanged;
   - boundary on `clip` (a string of exactly the maximum length is returned unchanged either
     way), `slash < 0` → `<= 0` (unreachable), double-checked locking in `DashboardService`.
3. **Logging-only branches**: `if (evicted) log.warn(...)`, the "seeded route" log line.
   Nothing observable changes.
4. **Timing and threads** (weak vs strong mutation): removing `Thread.sleep` in the retry loop,
   capping the backoff, `setDaemon`, `interrupt` in `stop()`. The fault stays local: results are
   identical, only time or thread state differ, and no test observes them without real waits.
5. **Real gaps**, killed by new tests: 32-character key boundary, a 512-character path,
   re-anchoring an unchanged head, batch size, a non-chunked `Transfer-Encoding`, headers that
   merely mention `GKSESSION` or another header's name.

### Areas with a low score

`LoadReport` (33 survivors: number formatting and sparkline geometry), `JvmSystemProbe` (13:
platform-dependent `/proc` parsing), `LoadMonitor` (7), `RouteService` (7, masked by the
reload-and-find that follows every write). Monitoring is display logic, the lowest risk.

## Mutation score improvement plan

1. **Inject a sleeper** in `AuditService` (as was done for clocks), so tests can assert the
   backoff sequence 200 ms → 30 s without waiting: kills the timing survivors.
2. **Monitoring**: table-driven tests for `LoadReport` formatting and sparkline points; an
   injectable `/proc/net/dev` path for `JvmSystemProbe`.
3. **Integration-only classes**: a scheduled (nightly) workflow running PiTest with the
   integration tests on `ProxyEntryFilter` and the repositories, kept out of the per-commit
   pipeline because of its cost.
4. **Track equivalent mutants** in the report rather than chasing them; keep the `core` gate at
   90% so an equivalent mutant cannot block a release.
5. Extend the gate from `core` to `audit` and `gateway.forward` once they reach 90%.
