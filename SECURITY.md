# Security policy

Security Gatekeeper sits in front of internal services and keeps a tamper-evident audit
log, so a vulnerability here can expose what it protects. Reports are welcome and handled
privately.

## Supported versions

Only the latest version receives security fixes; there are no backports.

| Version | Supported |
|---|---|
| Latest commit on `master` (Docker Hub `peppe289/security_gatekeeper:latest`, `:sha-<commit>`) | ✅ |
| Any earlier commit or image | ❌ (upgrade to the latest) |

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

Report it privately through GitHub: **Security → Report a vulnerability** on this
repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
Only the maintainer can read the report.

Please include:

- the affected version (commit SHA or image tag) and the relevant configuration;
- the component (proxy pipeline, forwarding, admin panel, audit log, container image…);
- steps to reproduce, or a proof of concept against your own deployment;
- the impact you observed or expect.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Triage: confirmed or not, severity rated with CVSS | within 14 days |
| Fix released | Critical 7 days, High 30 days, Medium 90 days, Low next release |

You are kept informed along the way. Once fixed, the issue is published as a GitHub
Security Advisory, with a CVE requested through GitHub when it applies, and you are
credited unless you prefer otherwise.

## Coordinated disclosure

Please keep the details private until a fix is released, or for at most 90 days from the
report, whichever comes first. If a fix needs longer, a disclosure date is agreed with you.
If the issue is being actively exploited, the advisory may be published earlier.

## Scope

In scope:

- bypassing a route check: unknown or disabled route, API key, rate limit;
- leaking credentials to an upstream (API key, admin session cookie) or letting an
  upstream set the admin session;
- admin panel: authentication, session, CSRF, brute-force protection, injection;
- audit log: tampering that verification does not detect, beyond the limits below;
- secrets exposed by the application, its logs or its container image.

Out of scope:

- vulnerabilities of the services behind the gateway;
- the limitations documented in the README (*Current limitations*), e.g. records written
  after the last anchor, or an attacker who holds the HMAC key or controls both the
  database and the anchor storage;
- deployments that ignore required settings (TLS, strong secrets, `GATEWAY_AUDIT_ANCHOR_DIR`);
- volumetric denial of service, social engineering, physical access;
- scanner output without a demonstrated impact.

## Good-faith research

Test only against your own deployment. Research that follows this policy is welcome and
will not be pursued.

## How the project protects itself

Dependency updates (Dependabot), secret scanning, static analysis and dependency scanning in
the CI/CD pipeline are described in [`docs/security.md`](docs/security.md) and
[`docs/Security_and_Quality.md`](docs/Security_and_Quality.md).
