# Security Gatekeeper

A containerized HTTP reverse proxy that exposes internal services on a public domain.
It comes with a web admin panel, per-route rate limiting, optional API keys and a
tamper-evident audit log (a SHA-256 hash chain stored in PostgreSQL).

```
https://<domain>/myservice/api/x   ──▶   http://localhost:8080/api/x
```

## Quick start

```bash
cp .env.example .env        # set POSTGRES_PASSWORD and GATEWAY_ADMIN_PASSWORD
docker compose up --build
```

- Admin panel: <http://localhost:8080/_gatekeeper/> (user `admin`)
- Sample route: <http://localhost:8080/whoami/>

## How it works

Every request outside `/_gatekeeper` goes through a pipeline of filters:

```
AuditFilter ─▶ RouteResolution ─▶ RouteEnabled ─▶ ApiKey ─▶ RateLimit ─▶ Forwarding
(records every outcome)                                             (calls the upstream)
```

| Outcome | HTTP |
|---|---|
| unknown prefix | 404 |
| route disabled | 503 |
| API key missing / wrong | 401 / 403 |
| rate limit exceeded | 429 + `Retry-After` |
| upstream unreachable / timed out | 502 / 504 |

Rejections are returned as `application/problem+json` (RFC 9457).

- **Routes.** The first path segment selects the route and is stripped before forwarding.
  Routes are managed from the admin panel and stored in PostgreSQL. Each instance keeps an
  in-memory copy and reloads it periodically (`gateway.routes.refresh-interval`), so
  several instances behind a load balancer stay in sync.
- **Forwarding.** Bodies are streamed in both directions. Hop-by-hop headers are removed,
  and `X-Forwarded-For/Proto/Host/Prefix` are added. The API key and the admin session
  cookie never reach the upstream. Redirects are passed back to the client unchanged, and
  upstream TLS certificates are validated.
- **API keys** (optional, per route). They protect an internal service that has no
  authentication of its own: only clients that send the key in the `X-Api-Key` header
  get through. The gateway stores only the key's SHA-256 hash and shows the key once.
  API keys suit programmatic clients (scripts, apps, devices). Browsers do not send
  custom headers, so leave web UIs public or rely on their own login.
- **Audit log.** The request thread only enqueues an event. A background thread extends
  the hash chain and writes to the database in batches, so auditing never slows down
  proxied traffic. Each instance (`gateway.node-id`) writes its own chain. The database
  rejects `UPDATE`s through a trigger. Verification from the admin panel recomputes the
  whole chain, so it also detects changes made by someone who bypassed the trigger.
- **Admin panel.** It has login brute-force protection, CSRF tokens and a strict
  Content-Security-Policy. Statistics are cached and recomputed at most every
  `gateway.dashboard.stats-refresh` (5 s by default). Nothing updates in real time.

## HTTPS

Terminate TLS on the public domain, in one of two ways:

- **On the gateway itself:** set `SERVER_SSL_ENABLED=true`, `SERVER_SSL_CERTIFICATE` and
  `SERVER_SSL_CERTIFICATE_PRIVATE_KEY` (PEM), plus `GATEWAY_SECURE_COOKIE=true`.
- **Behind a load balancer or TLS terminator:** set `SERVER_FORWARD_HEADERS_STRATEGY=native`
  and `GATEWAY_SECURE_COOKIE=true`.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` / `DATABASE_USERNAME` / `DATABASE_PASSWORD` | `jdbc:postgresql://localhost:5432/gatekeeper` | PostgreSQL connection |
| `GATEWAY_ADMIN_PASSWORD` | *(generated and logged at startup)* | admin panel password; `{bcrypt}…` hashes are accepted |
| `GATEWAY_NODEID` | hostname | identifies this instance's audit chain |
| `GATEWAY_RATELIMIT_DEFAULTBURSTCAPACITY` / `…DEFAULTREFILLPERSECOND` | 100 / 50 | default limits for new routes |
| `GATEWAY_ROUTES_SEED_0_PREFIX` / `…_TARGETURL` | — | routes created at first startup |
| `PORT` | 8080 | HTTP port |

Every setting is listed in `src/main/resources/application.yml`.

## Development

Requires Java 17. Integration tests need Docker, because they use Testcontainers.

```bash
./mvnw verify                           # unit and integration tests, coverage check
./mvnw -Pmutation verify                # adds PiTest mutation testing on the core package
./mvnw -Pbenchmark -DskipTests verify   # JMH benchmarks
```

Package layout:

| Package | Contents |
|---|---|
| `core` | pure-Java domain (token bucket, route policy, audit chain), with no framework dependencies |
| `gateway` | servlet entry point, filter pipeline, HTTP forwarder |
| `route` | route management (in-memory cache and PostgreSQL) |
| `audit` | asynchronous audit writer and chain verification |
| `ratelimit` | per-client token buckets with eviction |
| `admin` | admin panel and login throttling |
| `config` | configuration properties, security, shared beans |

## Continuous integration

GitHub Actions workflows live in `.github/workflows`:

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push, pull request | `./mvnw verify` (unit and integration tests, JaCoCo gate on `core`), PiTest with a blocking mutation threshold, Docker image build. On `master` it also publishes the JaCoCo and PiTest reports to GitHub Pages. |
| `security.yml` | push, pull request, weekly | GitGuardian secret scanning, Snyk scans of the Maven dependencies and the Docker image, SonarQube Cloud analysis with coverage. |
| `openjml.yml` | changes to `core` | OpenJML type check and static verification of the JML specifications (both blocking). |
| `benchmark.yml` | manual | JMH benchmarks, with results in the run summary. |
| `release.yml` | tag `v*` | Multi-arch image (amd64, arm64) published to `ghcr.io/<owner>/<repository>`. |

Dependabot (`.github/dependabot.yml`) opens weekly updates for Maven, the Docker base images
and the GitHub Actions.

One-time setup on GitHub:

- **Pages:** Settings › Pages › Source: *GitHub Actions* (for the published reports).
- **Secrets** (Settings › Secrets and variables › Actions). A scanner without its token is
  skipped, not failed.

  | Secret | Where to get it |
  |---|---|
  | `GITGUARDIAN_API_KEY` | GitGuardian dashboard › API › Personal access tokens |
  | `SNYK_TOKEN` | Snyk › Account settings › Auth token |
  | `SONAR_TOKEN` | SonarQube Cloud › My account › Security |

- **SonarQube Cloud:** import the repository there first. If the organization or project
  key differs from the defaults (`<owner>` and `<owner>_<repository>`), set the repository
  variables `SONAR_ORGANIZATION` and `SONAR_PROJECT_KEY`. Turn off *Automatic Analysis*
  in the project settings, since the analysis runs from CI.

## Current limitations

- One upstream per route: no load balancing or upstream health checks.
- No WebSocket or other protocol upgrades: plain HTTP requests only.
- Rate limits and statistics are per instance, not shared across nodes.
