# Releasing

This repository uses orchestrated releases via [clawosiris/release-orchestrator](https://github.com/clawosiris/release-orchestrator).

## How Releases Work

1. **Do NOT create releases manually** in this repository
2. All releases are triggered from the [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
3. The orchestrator manages versioning, changelogs, and cross-repo coordination

## Creating a Release

### Stable Release
1. Go to [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
2. Trigger the release workflow with type `patch`, `minor`, or `major`
3. The release workflow will build and attach:
   - `gvm-gateway` Arch Linux packages (`.pkg.tar.zst`)
   - `gvm-gateway` Debian packages (`.deb`)
   - `gvm-gateway` OCI image archives (`.oci.tar`)
   - matching `.sha256` checksum files
   - SBOM archives

### Nightly / Alpha Build
1. Go to [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
2. Trigger the release workflow with type `alpha`
3. Nightly/alpha package artifacts are published with prerelease-safe package versions so stable releases remain the upgrade target.

### Pre-releases
- `alpha` — Early development builds (nightlies)
- `beta` — Feature-complete, testing phase
- `release-candidate` — Final testing before stable

## Local Development

For local testing without releasing:
```bash
cargo build --release
cargo test
./scripts/install-nfpm.sh
./scripts/package-build.sh --packager deb --version "$(./scripts/workspace-version.sh)"
./scripts/package-build.sh --packager archlinux --version "$(./scripts/workspace-version.sh)"
./scripts/oci-build.sh --tag local/gvm-gateway:dev
```

Package smoke tests use Docker in CI:

```bash
./scripts/package-smoke.sh --packager deb
./scripts/package-smoke.sh --packager archlinux
```

Compose stack validation and OCI archive export are also covered in CI/release automation.

## Packaging Notes

- The first pass packages the unified `gvm-gateway` binary.
- Packages also ship an example config at `/etc/gvm-gateway/gvm-gateway.toml`.
- OCI image builds ship a container-oriented config at `/etc/gvm-gateway/gvm-gateway.toml` with `0.0.0.0:8080` and a shared `/run/gvmd` socket contract.
- systemd service/unit packaging is intentionally deferred until the runtime contract and service defaults settle.

## Questions?

See the [release-orchestrator README](https://github.com/clawosiris/release-orchestrator) for full documentation.
