# CI/CD report

## Pipeline overview

`.github/workflows/ci.yml` runs on every **push** and **pull request** to `master` (and
manually through `workflow_dispatch`). It is the quality gate every change must pass. The
other workflows build on it:

```
push / PR ─▶ ci.yml ── build-and-test ┐
                    ├─ mutation        ├─ all green ─▶ docker-build.yml ─▶ Docker Hub
                    └─ docker          ┘  (push only)
          ─▶ security.yml (GitGuardian, Snyk, SonarQube)   ─▶ openjml.yml (JML, on core changes)
tag v*  ─▶ release.yml (multi-arch image on GHCR)
```

The three CI jobs run **in parallel**: feedback in about one minute (build and test 60 s,
mutation 40 s, image 44 s on the latest run).

## Stages of `ci.yml`

### 1. Build and test
1. **Checkout** and **JDK 25** (Temurin) with the Maven cache.
2. **`./mvnw -B -ntp verify`** compiles, runs the **357 tests** (325 unit, 32 integration
   with a real PostgreSQL started by Testcontainers on the runner's Docker), produces the
   JaCoCo report and enforces the **coverage gates** (95% on `core`, 85%/80% project-wide).
   Any failing test or coverage drop fails the job.
3. **Test report**: `dorny/test-reporter` publishes the JUnit results as a check on the
   commit or pull request.
4. **Coverage summary**: the run summary shows line and branch coverage for `core` and for
   the whole project.
5. **Artifacts**: the JaCoCo report and the built jar (kept 14 days).

### 2. Mutation testing (PiTest)
Runs PiTest on `core` with a **blocking mutation threshold** of 90%. The run summary lists
the killed mutants and every survivor (class, method, line, mutator); the HTML/XML report is
attached as an artifact.

### 3. Docker image build
Builds the `Dockerfile` with Buildx without pushing, so a broken image is caught on the pull
request rather than at release. Layers are cached in the GitHub Actions cache.

### After CI
`docker-build.yml` starts only when CI **succeeds on a push** to `master`. It builds the
commit CI tested (`head_sha`) for amd64 and arm64 and pushes it to Docker Hub as `latest` and
`sha-<commit>`. Pull requests never publish. Details in [`Docker.md`](Docker.md).

## Build reproducibility

| Measure | Effect |
|---|---|
| **Maven Wrapper** (`mvnw`, Maven 3.10.1 pinned in `.mvn/wrapper`) | same Maven everywhere, nothing to install |
| **JDK 25** pinned in `pom.xml` (`java.version`), the workflows and the Docker images | same compiler and runtime in CI, locally and in the container |
| **Dependency versions** managed by the Spring Boot parent; test stack and plugins pinned explicitly; no version ranges | the dependency tree changes only through a commit |
| **Ephemeral runners** (`ubuntu-latest`) | every run starts clean: no state left by earlier builds ("works on my machine") |
| **Testcontainers** with `postgres:18-alpine`, the same image as production | integration tests run against the real database, not an in-memory substitute |
| **Docker build** runs the same wrapper inside a pinned JDK image | the published jar does not depend on the runner |
| **Immutable artifacts**: images tagged with the commit SHA, built once from the tested commit | what was tested is exactly what is published |
| **Dependabot** (Maven, Docker, Actions) | updates arrive as pull requests and go through the same pipeline |

Known limits: actions are pinned to major versions (Snyk to a commit SHA), base images to
tags rather than digests, and `ubuntu-latest` moves over time. Dependabot keeps these
current, at the cost of bit-for-bit reproducibility.

## Code quality

- **Fail fast**: tests, coverage and mutation thresholds run on every commit; a regression
  blocks the merge and the image publication.
- **Quality gates**: JaCoCo (95% on `core`, 85%/80% overall) and PiTest (90% on `core`) are enforced by the
  build itself (`pom.xml`), so they apply locally too, not only in CI.
- **Formal verification**: `openjml.yml` type-checks and statically verifies the JML
  specifications of `core` (both blocking) whenever `core` changes.
- **Security**: `security.yml` runs GitGuardian secret scanning, Snyk (dependencies and image)
  and SonarQube Cloud on every push and weekly. A scanner without its token is skipped with a
  notice, not failed (see `Security_and_Quality.md`).

## Pipeline security

- **Least privilege**: workflows default to `contents: read`. Only the build job gets
  `checks: write`, `release.yml` `packages: write`, and the mutation-badge job (no project
  code, master only) `contents: write`.
- **Secrets** (Docker Hub, scanners) live in encrypted repository secrets, never in files.
  Pull requests from forks receive no secrets, and the jobs that need them are skipped.
- **Concurrency**: a newer push cancels the older run on the same ref, saving minutes and
  avoiding outdated results.

## Result

The latest CI runs on `master` are all green. Every published image corresponds to a commit
that passed tests, coverage, mutation testing and the image build.
