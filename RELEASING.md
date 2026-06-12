# Releasing

This repository releases from in-repo GitHub Actions workflows. Release file
changes land through a normal PR, release tags are created from merged PRs that
carry the `release` label, and publishing runs only from pushed `v*` tags.

## Release Model

The release flow has three phases:

1. **Prepare**: `Prepare Release` updates `Cargo.toml`, refreshes `Cargo.lock`,
   and opens a release-preparation PR against `main`.
2. **Tag**: `Create Release Tag` runs when a PR into `main` closes. If the PR was
   merged, has the `release` label, and changed the workspace version, it creates
   annotated tag `v<version>` at the merge commit.
3. **Publish**: `Publish Release` runs on pushed tags matching `v*`, validates
   the tag against `Cargo.toml`, and publishes release assets.

The `Cargo.toml` workspace version on `main` represents the last released version
or the current release candidate. Do not bump to a synthetic next-dev version
after a release.

## Creating a Release

1. Open the `Prepare Release` workflow in GitHub Actions.
2. Run it with the target semantic version without a leading `v`, for example
   `0.4.0` or `0.4.0-alpha.1`.
3. Review the generated PR. It should update the workspace version and
   `Cargo.lock` only when the lockfile needs refreshing.
4. Apply the exact PR label `release`.
5. Merge the PR into `main` after required checks pass.
6. Confirm that `Create Release Tag` created tag `v<version>`.
7. Confirm that `Publish Release` completed for that tag.

`Publish Release` builds and uploads:

- `gvm-gateway` Debian packages (`.deb`)
- `gvm-gateway` Arch Linux packages (`.pkg.tar.zst`)
- `gvm-gateway` OCI image archives (`.oci.tar`)
- matching `.sha256` checksum files
- SBOM archives

## Retry and Recovery

- If the preparation workflow fails before opening a PR, rerun `Prepare Release`
  with the same version.
- If the preparation PR needs changes, update the PR branch through the workflow
  or by editing the PR branch. Keep all release-version file changes in the PR.
- If the PR merged without the `release` label, add a new release-preparation PR
  or create the tag manually only after verifying `Cargo.toml` matches the
  intended version.
- If tag creation failed after a labeled merge, rerun `Create Release Tag`.
- If publishing failed, rerun `Publish Release` for the existing `v<version>` tag.
- Do not force-push release tags as part of normal release recovery. If a tag
  points at the wrong commit, stop and resolve that deliberately.

## Pre-Releases

Use semantic pre-release versions in `Prepare Release`, for example:

- `0.4.0-alpha.1`
- `0.4.0-beta.1`
- `0.4.0-rc.1`

Pre-release package artifacts are published with pre-release-safe package
versions so stable releases remain the upgrade target.

## Local Development

For local testing without releasing:

```bash
cargo build --locked --release -p gvm-gateway
cargo test
./scripts/package-build.sh --packager deb --version "$(./scripts/workspace-version.sh)"
./scripts/package-build.sh --packager archlinux --version "$(./scripts/workspace-version.sh)"
./scripts/oci-build.sh --tag local/gvm-gateway:dev
```

Local package builds require Docker and `cosign`. `package-build.sh` verifies the
signed `ghcr.io/goreleaser/nfpm` image before running it.

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
