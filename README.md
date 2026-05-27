# rust-gvm-api

[![CI](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml)
[![Security](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml)

> [!NOTE]
> **Releases** are managed via the [release-orchestrator](https://github.com/clawosiris/release-orchestrator).
> To create a nightly/alpha build, create an alpha release in the orchestrator.
> See [RELEASING.md](./RELEASING.md) for details, including automated Debian and Arch Linux package artifacts.

REST and gRPC API servers for [Greenbone Vulnerability Management (GVM)](https://greenbone.github.io/docs/latest/), built on top of [rust-gvm](https://github.com/clawosiris/rust-gvm).

## Overview

This project provides modern, standards-compliant API layers on top of the Greenbone Management Protocol (GMP). Instead of speaking GMP's raw XML over Unix sockets or SSH, consumers can interact via familiar REST or gRPC interfaces.

### Crates

| Crate | Description |
|-------|-------------|
| `gvm-rest-api` | RESTful API server (OpenAPI 3.1, JSON, axum) |
| `gvm-grpc-api` | gRPC API server (Protocol Buffers, tonic, server-streaming) |

### Architecture

```
┌──────────────┐     HTTP/JSON     ┌───────────────┐
│  REST Client │◄─────────────────►│ gvm-rest-api  │
└──────────────┘                   └───────┬───────┘
                                           │
┌──────────────┐     gRPC/Proto    ┌───────┴───────┐     GMP/XML      ┌──────┐
│  gRPC Client │◄─────────────────►│ gvm-grpc-api  │◄───────────────►│ gvmd │
└──────────────┘                   └───────────────┘  Unix/SSH/TLS    └──────┘
                                           │
                                   ┌───────┴───────┐
                                   │  rust-gvm     │
                                   │  (gvm-client) │
                                   └───────────────┘
```

Both API servers use `gvm-client` from [rust-gvm](https://github.com/clawosiris/rust-gvm) to communicate with `gvmd` over the Greenbone Management Protocol.

## Status

🚧 **Early development** — not yet functional. See the [OpenSpecs](spec/) for the design.

## Getting Started

### Prerequisites

- Rust 1.75.0+ (see `rust-toolchain.toml`)
- A running GVM/gvmd instance (for integration testing)
- [rust-gvm](https://github.com/clawosiris/rust-gvm) (pulled as a git dependency)

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Development

```bash
# Install dev tools
make setup-tools

# Install pre-commit hooks
make setup-hooks

# Run full CI locally
make ci
```

### OCI Image Build

Build the gateway image with either Docker or Podman:

```bash
./scripts/oci-build.sh --tag local/gvm-gateway:dev
```

The image is built from [Containerfile](./Containerfile) as a multi-stage OCI-compatible runtime image for the `gvm-gateway` binary. Release workflows also export the result as an OCI archive artifact.

### Compose Dev Stack

Start a local gateway + gvmd stack with either Docker Compose or Podman Compose:

```bash
./scripts/compose-dev.sh up -d --build
```

The stack definition in [compose.yaml](./compose.yaml) is based on the official Greenbone Community container topology, but trims it to the services needed for `gvmd` plus the gateway. On the first boot, feed and data initialization can take several minutes before `gvmd` is ready.

Useful follow-up commands:

```bash
./scripts/compose-dev.sh logs -f gvmd gvm-gateway
./scripts/compose-dev.sh down
```

### Container Runtime Contract

- Default container config: [packaging/gvm-gateway.container.toml](./packaging/gvm-gateway.container.toml)
- Listener: `0.0.0.0:8080`
- gvmd socket mount: `/run/gvmd`
- Required backend endpoint: `GVM_GATEWAY_GVMD_ENDPOINT=unix:///run/gvmd/gvmd.sock`
- Optional telemetry endpoint: `GVM_GATEWAY_OTLP_ENDPOINT`
- Optional shutdown tuning: `GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS`
- Optional REST security overrides:
  - `GVM_GATEWAY_CORS_ALLOWED_ORIGINS`
  - `GVM_GATEWAY_RATE_LIMIT_WINDOW_SECS`
  - `GVM_GATEWAY_RATE_LIMIT_GLOBAL_PER_WINDOW`
  - `GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW`

## Documentation

- [REST API OpenSpec](spec/rest-api/openspec.md)
- [gRPC API OpenSpec](spec/grpc-api/openspec.md)

## License

Licensed under [AGPL-3.0-or-later](LICENSE).
