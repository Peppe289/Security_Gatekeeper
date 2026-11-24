# Code security report

Security checks run in GitHub ("shift left"): static analysis of the code, secret detection
and software composition analysis of the dependencies, each with a quality gate.

## 1. Code scanning configuration

`.github/workflows/codeql-analysis.yml`:

- **CodeQL** (`github/codeql-action` v4), language `java-kotlin`, **`security-and-quality`**
  query suite (security queries plus maintainability and correctness ones).
- Manual build of the production code with the Maven Wrapper on JDK 25 (CodeQL supports Java
  up to 26); test code is not analysed, it is not shipped.
- Runs on push and pull request to `master`, **weekly** (new queries can flag unchanged
  code) and on demand. Results appear in *Security › Code scanning*.
- Only the analysis job gets `security-events: write`; the workflow default is read-only.

## 2. Secret scanning setup

- **Secret scanning** and **push protection** are enabled (verified through the API): a push
  containing a known token format is blocked before it reaches the repository.
- Secrets never live in files: `.env` is git- and docker-ignored, compose reads
  `${VAR:?…}` and refuses to start without them, CI secrets are repository secrets.
- No custom pattern yet. Candidate: the gateway's own API keys (`gk_` + 43 base64url
  characters), so a leaked route key would be caught too.
- GitGuardian scans the pipeline as a second layer (`security.yml`, Lab 8).

## 3. Dependabot configuration

`.github/dependabot.yml`: **weekly** updates for Maven, Docker base images and GitHub Actions;
minor and patch Maven updates and all Actions updates are **grouped** into one pull request
each; major versions of `eclipse-temurin` are ignored, as the JDK must be bumped together with
`pom.xml` and the workflows. Every update is assigned to the maintainer, and `CODEOWNERS`
requests the maintainer's review. Dependabot **alerts** and **security updates** are enabled.

## 4. Security integration in CI/CD

| Gate | Where | Fails when |
|---|---|---|
| CodeQL | `codeql-analysis.yml` | an **open** High/Critical alert (security severity ≥ 7.0) or error-level finding exists on the analysed ref |
| Dependabot alerts | `security.yml` | an **open** High/Critical Dependabot alert exists |
| Push protection | GitHub | a push contains a recognised secret |
| Tests, coverage, mutation | `ci.yml` | see `CICD.md` |

Both gates query the alerts API, so an alert **dismissed with a written reason** no longer
blocks, while the raw analysis would. The lab example counts *every* Dependabot alert, closed
ones included, and suggests write permissions; here the token only has
`vulnerability-alerts: read`. Images are published only after CI is green.

## 5. Security policy

Reporting and disclosure are in [`SECURITY.md`](../SECURITY.md): private vulnerability
reporting (enabled), coordinated disclosure within 90 days, advisory and CVE through GitHub.

- **Prioritisation** by CVSS severity: Critical fixed within 7 days, High 30, Medium 90, Low
  in the next release. High and Critical block the pipeline until fixed or formally accepted.
- **Accepting a risk** requires a dismissal with a written justification in code scanning,
  so the reasoning stays on record.
- **Dependabot pull requests** are merged only with every check green and after the code
  owner's review; grouped minor/patch updates are reviewed together, majors by hand.
- **Secrets and rotation**: the audit HMAC key rotates without breaking verification (the old
  key moves to `gateway.audit.previous-hmac-keys`); route API keys are stored as SHA-256 hashes
  and rotated from the panel; the admin password is required, never generated or logged; CI
  tokens (Docker Hub, Codecov, scanners) are personal access tokens, revoked and replaced on
  suspicion.

## 6. Security metrics

| Source | Found | Outcome |
|---|---|---|
| Code scanning | **11**: 2 Critical, 2 High, 1 Medium, 6 quality (1 warning, 5 notes) | 8 fixed, 3 dismissed, **0 open** |
| Secret scanning | **0** | — |
| Dependabot alerts | **0** | 3 update PRs merged the day they were opened |

**Time to remediate**: first analysis at 14:59 UTC, the 8 fixes verified by the next analysis
at 15:10 (**11 minutes**), the 3 dismissals at 15:13.

- **Fixed**: password written to the log (High) → now required; log injection (Medium) →
  prefix validated before use; 6 quality findings → defensive parsing, no one-shot
  `SecureRandom`.
- **Dismissed as by design** (static analysis cannot know the application): *SSRF* in the
  forwarder (Critical, 2 locations), since forwarding to the admin-configured upstream is the
  product's purpose; the client controls only path and query, and `requireSameOrigin` now
  rejects any other scheme, host or port. *CSRF disabled* (High) only on the proxy chain,
  where requests carry no gateway credential.

The dismissed alerts are classic static-analysis false positives: each rule is right in
general, but it ignores what a reverse proxy is for.
