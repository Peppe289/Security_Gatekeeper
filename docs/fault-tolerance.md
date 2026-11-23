# Fault-injection experiment: database outage

How the gateway behaves when PostgreSQL goes down and comes back, and whether data
survives the containers being recreated. This repeats Step 3.3 of the Lab 2a assignment
on this project's own stack.

## Setup

- Stack from `docker-compose.yml` (gateway + PostgreSQL 18), started in an isolated
  Compose project with its own volumes and throwaway credentials.
- A temporary override (not committed) added an `nginx:1.29-alpine` upstream and the seed
  route `/echo` → `http://echo:80`, so there was something to proxy.
- Probes from the host: requests to `/echo/` (proxied, audited), `/_gatekeeper/health`
  (5 s client timeout), the admin dashboard, the container health status reported by
  Docker, and the row count of `audit_log`. Audit integrity checked with the panel's
  *Verify integrity* action.

## Procedure and results

| Phase | Action | Observed |
|---|---|---|
| Baseline | stack up | all services `healthy`; 20 × `/echo/` → 200 (max 91 ms); 20 audit rows; chain intact (20 records, 1 anchor) |
| Fault | `docker compose stop db` | see below |
| During outage (≈ 3 min) | 80 × `/echo/`, sampled every ~28 s | **every request 200**, max 13 ms; gateway turned `unhealthy` between t+28 s and t+56 s |
| Recovery | `docker compose start db` | within 9 s: DB `healthy`, `/health` → 200, gateway `healthy`, backlog written (100 rows) |
| Integrity | panel verification | **chain intact: 100 records, 2 anchors** |
| Persistence | `docker compose down` (no `-v`), then `up` | 100 rows, the `/echo` route and the anchors still there; `/echo/` → 200; chain intact (105 records, 4 anchors) |

### During the outage

| Component | Behaviour |
|---|---|
| Proxy (`/echo/`) | Kept working: routes are served from the in-memory snapshot. The periodic refresh fails every 10 s (logged as an error) and the snapshot is kept. |
| Audit | Events stayed queued in memory; the writer retried with exponential backoff (200 ms → 30 s cap, e.g. *"not persisted (CannotCreateTransactionException); retrying in PT25.6S"*). **No event was lost**: all 80 were persisted after recovery, in order, with valid signatures. |
| `/_gatekeeper/health` | **503 after 30 s**, the HikariCP default `connection-timeout`. Docker's probe gives up after 3 s, so each check fails by timeout; after 3 retries (≈ 45 s) the container is `unhealthy`. |
| `/health/liveness`, `/health/readiness` | 200 in a few ms: neither group includes the database. |
| Admin panel | 500 after 30 s (it reads statistics from the database). |
| `restart: on-failure` | Not triggered, correctly: the process never exited. |

## Findings

1. **Graceful degradation works.** A database outage does not stop proxied traffic, and
   the audit log loses nothing as long as the outage fits in the queue (50,000 events by
   default; beyond that new events are dropped and counted, not tested here).
2. **Recovery is automatic.** No restart is needed: the connection pool reconnects, the
   audit backlog is flushed and the next anchor covers it.
3. **Data is durable.** Named volumes keep the database and the anchor files across
   `down`/`up`.
4. **The health signal is slow.** A DB-dependent health request blocks a worker thread for
   30 s. With a probe every 15 s, up to two threads are tied up by health checks alone, and
   every panel request waits 30 s before failing.
5. **The health signal is ambiguous.** `/health` reports the gateway as unhealthy while it
   is serving traffic correctly. An orchestrator that restarts unhealthy containers would
   make things worse: a gateway restarted during the outage cannot run its migrations or
   load its routes, so it would go from degraded to down.

## Possible improvements

- Lower `spring.datasource.hikari.connection-timeout` (e.g. 3–5 s), so health checks and
  panel requests fail fast during an outage.
- Point the container healthcheck at `/_gatekeeper/health/readiness`, which reflects
  whether the gateway can serve traffic, and keep `/health` (database included) for
  monitoring and alerts.
- Report audit backlog and dropped events in the readiness or monitoring output, so a long
  outage is visible before the queue fills up.
