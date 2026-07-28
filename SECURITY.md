# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

We support the latest minor release with security patches. Once a new minor or major version is published, prior versions receive patches only for critical vulnerabilities at maintainer discretion.

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, use **GitHub Private Vulnerability Reporting**:

1. Go to the [Security Advisories](https://github.com/greenbone-hive/rust-gvm-api/security/advisories) tab
2. Click **"Report a vulnerability"**
3. Fill in the details — affected crate(s), reproduction steps, and impact assessment

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Patch timeline** depends on severity:
  - **Critical / High**: Target fix within 7 days
  - **Medium**: Target fix within 30 days
  - **Low**: Next scheduled release
- We will coordinate disclosure timing with you. We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) practices.

### What qualifies

- Authentication/authorization bypass in REST or gRPC APIs
- Credential exposure in API responses, logs, or headers
- Injection vulnerabilities (SQL, XML, command)
- Improper input validation leading to resource exhaustion (DoS)
- TLS/transport layer vulnerabilities
- Dependency vulnerabilities with a viable attack path through our code

### What doesn't qualify

- Issues in upstream dependencies without a demonstrated attack path through rust-gvm-api
- Rate limiting or brute-force concerns (expected to be handled by deployment infrastructure)

## Security Measures

### Dependency Auditing

- **[cargo-audit](https://github.com/rustsec/rustsec)** runs in CI on every push and weekly via the Security workflow
- **[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)** enforces license compliance, bans, and source restrictions (see [`deny.toml`](deny.toml))
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** monitors Cargo and GitHub Actions dependencies with weekly update PRs
- **[cargo-machete](https://github.com/bnjbvr/cargo-machete)** checks for unused dependencies in CI

### Code Quality

- `cargo clippy` with `-D warnings` in CI
- `#[deny(unsafe_code)]` — no unsafe blocks in any crate
- MSRV tested (currently Rust 1.88.0)
- SBOM (CycloneDX) generated on every release and nightly build

## Changelog

| Date | Change |
|------|--------|
| 2026-03-20 | Initial security policy |
