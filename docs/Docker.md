# Containerization report

## Dockerfile

Multi-stage build on `eclipse-temurin:25` Alpine images.

- **Build stage** (JDK): dependencies are resolved in their own layer
  (`dependency:go-offline`) before the sources are copied, so a code change does not
  download them again. It runs on `$BUILDPLATFORM`: the jar does not depend on the CPU, so
  Maven runs natively once and only the runtime stage is built per architecture.
- **Runtime stage** (JRE only): the Spring Boot layered jar is copied in four layers,
  least to most frequently changing; no JDK, Maven or sources in the final image.

Anti-patterns avoided:

| Anti-pattern | How it is avoided |
|---|---|
| Running as root | dedicated `gatekeeper` system user (`USER gatekeeper`) |
| Fat image with build tools | multi-stage build, JRE-only Alpine runtime |
| Rebuilding everything on each change | layer order + layered jar |
| `latest` or floating base images | JDK/JRE 25 and `postgres:18-alpine` pinned; Dependabot proposes updates |
| Secrets in the image | none: everything comes from the environment at run time |
| Large or leaky build context | `.dockerignore` excludes `target/`, `.git`, IDE files and `.env` |
| No health information | `HEALTHCHECK` on the Actuator endpoint |
| JVM ignoring container limits | `-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError` |

## docker-compose.yml

- **Services**: the gateway and PostgreSQL 18. The gateway starts only when the database is
  `healthy` (`depends_on: condition: service_healthy`).
- **Health checks** on both services (`pg_isready`; Actuator `/_gatekeeper/health`) and
  `restart: on-failure` on both.
- **Named volumes**: `db-data` for the database and `audit-anchors` for the signed audit
  anchors, which must live outside the database.
- **Secrets**: the passwords and the audit HMAC key come from an uncommitted `.env`; the
  `${VAR:?…}` syntax makes Compose refuse to start if one is missing. Only the gateway
  port is published; the database is reachable only on the internal network.

## CI/CD workflow

`.github/workflows/docker-build.yml` runs after the `CI` workflow completes on `master`:

- it proceeds only if CI **succeeded** and was triggered by a **push** (never by a pull
  request);
- it checks out `workflow_run.head_sha`, the exact commit CI tested;
- it builds for `linux/amd64` and `linux/arm64` (QEMU only emulates the runtime stage)
  and pushes `peppe289/security_gatekeeper:latest` and `:sha-<commit>`, so every image
  maps to a commit;
- it uses a read-only `GITHUB_TOKEN`, a Docker Hub access token (not the password), and
  skips the push with a notice when the secrets are missing.

## Audit of the reference workflow

Issues found in the workflow proposed by the lab, and how this project handles them:

1. **Pushes after pull-request CI runs**: it checks only `conclusion`, not the triggering
   event. Here: `event == 'push'` is required too.
2. **Builds the wrong commit**: `checkout` without `ref` takes the latest `main`, which CI
   may not have tested. Here: `head_sha`.
3. **Redundant Maven build**: `mvn package` on the runner, with JDK 21, is wasted when the
   Dockerfile builds the jar itself, and may not match the project's JDK.
4. **Multi-arch without QEMU**: `platforms: linux/amd64,linux/arm64` with no
   `setup-qemu-action`; any `RUN` step of the arm64 stage fails with `exec format error`.
5. **Masked tags**: the image name uses `secrets.DOCKER_USERNAME`, so tags show as `***`
   in logs. Here: a plain repository variable.
6. **Untraceable tags**: `latest` plus a static `version-tag`. Here: `sha-<commit>`.
7. **Dead manual trigger**: on `workflow_dispatch` there is no `workflow_run`, so the
   `if` is false and the job is always skipped.
8. **No `permissions` block** and outdated action versions.

## Fault tolerance

Stopping PostgreSQL under load ([full report](fault-tolerance.md)):

- proxied traffic kept working (80/80 requests → 200), served from the in-memory routes;
- no audit event was lost: queued, retried with backoff, persisted after recovery,
  chain verified intact;
- recovery was automatic within 9 s; data and anchors survived `down`/`up`;
- weak spot: the DB health check takes 30 s (HikariCP timeout) and marks the gateway
  `unhealthy` while it still serves traffic.

## Lessons learned

- **Major database upgrades need a migration**: the old PostgreSQL 17 volume made the 18
  container crash-loop; dump/restore or `pg_upgrade` is needed, not just a new tag.
- **`$BUILDPLATFORM` requires BuildKit**: the legacy builder leaves it empty.
- **"Running" is not "working"**, and **"unhealthy" is not "broken"**: the health check
  must match what the orchestrator will do with it.
