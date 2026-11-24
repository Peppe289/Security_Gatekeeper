# JML verification report

## Verification setup

- **Scope**: the `core` package, pure Java with no framework or I/O (token bucket, route
  policy, audit chain, SHA-256). Controllers and Spring wiring are left out, as the lab
  advises.
- **OpenJML 21.0.29** (bundles a JDK 21 and the Z3 prover). `core` stays within Java 21
  language features and is checked without `--release`: OpenJML ships JML specs only for its
  own JDK. `src/main/jml` holds corrected specifications of JDK classes (`--specs-path`).
- **CI** (`.github/workflows/openjml.yml`, on every change to `core`, its tests or the specs),
  all blocking: `openjml -check` (type check), `openjml -esc` (static), and a RAC job:
  `openjml -rac -d target/rac`, then `mvn -Prac test` runs the 121 `core` unit tests on the
  instrumented classes instead of `target/classes`.

## Specifications added

| Class | Invariants | `requires` | `ensures` | Exceptional cases | `pure` |
|---|---|---|---|---|---|
| `TokenBucket` | 4 | 13 | 22 | 6 | 6 |
| `RoutePolicy` | 5 | 11 | 14 | 2 | 12 |
| `AuditRecord` | 4 | 9 | 14 | 1 | 14 |
| `AuditChain` | 2 | 5 | 8 | 1 | 2 |
| `AuditChainVerifier` | 3 | 4 | 6 | 1 | 3 |
| `PolicyEvaluator` | – | 2 | 6 | – | 3 |
| `Sha256` | – | 1 | 3 | – | 3 |

18 invariants, 45 preconditions, 73 postconditions, plus loop invariants and variants
(`maintaining`/`decreasing`) in `isValidPrefix` and `isHexDigest`. Examples: the bucket
always holds `0 <= tokens <= capacity`; `checkApiKey` returns only `ALLOW`, `API_KEY_MISSING`
or `API_KEY_INVALID`; invalid route arguments are an `exceptional_behavior` with
`signals_only IllegalArgumentException`.

## ESC results

**56 methods proved, 0 warnings; 6 excluded with `skipesc`**, each with its reason in the
source: bodies built on JDK classes without usable specs (`MessageDigest` in `Sha256.hex`,
`StringBuilder` in `AuditRecord.computeHash`/`field`, `java.net.URI` in
`RoutePolicy.isValidTargetUrl`), a validation helper whose consecutive calls the prover
cannot relate, and `toString`. Their contracts are still used to verify the callers.
With the corrected `URI` spec ESC got further on `isValidTargetUrl`, but stopped on the
specs of `String.toLowerCase(Locale)` and `Locale`: the exclusion stays.

## RAC results

| Step | Reports | Cause and fix |
|---|---|---|
| 1 | 91 test **errors** | `NoClassDefFoundError: org/jmlspecs/lang/internal/bigint`: these JML types live in the `java.base` of OpenJML's JDK 21. Packaged into a jar on the test classpath. |
| 2 | 491 | **Library spec**: OpenJML's `URI` getters are non-null by default, the JDK returns `null` for absent parts. Fixed in `src/main/jml/java/net/URI.jml`. |
| 3 | 230 | **Our own spec bug**: the new `URI(String)` had a normal and an exceptional case with the same precondition, so every call violated one. Rewritten as one `behavior` case. |
| 4 | **71** | Invariants on leaving a constructor that rejected its arguments. |

Debugging lesson: the first run looked green (121/121) because **RAC prints violations
without failing the test**, and the documented `racexceptions` property had no effect. A
deliberate violation (`checkEnabled(null)`) confirmed that RAC was really checking, and CI now
gates on the reports instead of on the test result.

The 71 remaining reports occur **only** when a constructor throws `IllegalArgumentException`
before assigning its fields (checked: valid constructions report nothing). The object is never
returned, and ESC proves every constructor's normal exit, so the CI gate tolerates exactly this
message and fails on any other violation.

## Verification success

- **Statically verified**: all specifications of the 56 proved methods (constructors
  included, on normal termination).
- **Checked at run time**: every specification exercised by the 121 `core` tests, including
  the 6 `skipesc` methods, with **no violation** besides the analysed constructor case.
- **Failed and fixed**: one specification, our own `URI` constructor contract.

## Lessons learned

- A failure may be a wrong **specification**, ours or a library's, not wrong code: three of
  four RAC findings were spec or setup issues.
- ESC and RAC are complementary: ESC covers all inputs but stops on unspecified libraries
  (hence `skipesc`); RAC checks those methods on real runs, limited to the inputs the tests
  provide.
- A green run proves nothing until a known violation shows that the checker can fail.
- `requires … else`-style specs need care: two cases with the same precondition must not
  promise incompatible outcomes.
- Keeping the verified code small and framework-free (`core`) is what made it verifiable.
