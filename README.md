# rust-gvm-api

[![CI](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml)
[![Security](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml)

> [!NOTE]
> **Releases** are managed via the [release-orchestrator](https://github.com/clawosiris/release-orchestrator).
> To create a nightly/alpha build, create an alpha release in the orchestrator.
> See [RELEASING.md](./RELEASING.md) for details, including automated Debian and Arch Linux package artifacts.

REST and gRPC API servers for [Greenbone Vulnerability Management (GVM)](https://greenbone.github.io/docs/latest/), with MCP planned as a peer API surface, all built on top of [rust-gvm](https://github.com/clawosiris/rust-gvm).

## Overview

This project provides modern, standards-compliant API layers on top of the Greenbone Management Protocol (GMP). Instead of speaking GMP's raw XML over Unix sockets or SSH, consumers interact through higher-level gateway surfaces such as REST, gRPC, and planned MCP tooling.

### Crates

| Crate | Description |
|-------|-------------|
| `gvm-rest-api` | RESTful API server (OpenAPI 3.1, JSON, axum) |
| `gvm-grpc-api` | gRPC API server (Protocol Buffers, tonic, server-streaming) |
| `gvm-gateway-*` | Shared gateway core and adapters that will also host MCP |

### Architecture

```
┌──────────────┐     HTTP/JSON     ┌──────────────────┐
│  REST Client │◄─────────────────►│ gvm-gateway-rest │
└──────────────┘                   └────────┬─────────┘
                                            │
┌──────────────┐     gRPC/Proto    ┌────────┴─────────┐
│  gRPC Client │◄─────────────────►│   gvm-grpc-api   │
└──────────────┘                   └────────┬─────────┘
                                            │
┌──────────────┐     MCP Tools     ┌────────┴─────────┐
│  MCP Client  │◄─────────────────►│ gvm-gateway-mcp │
└──────────────┘                   └────────┬─────────┘
                                            │
                                   ┌────────┴─────────┐
                                   │  gvm-gateway-*   │
                                   │ shared core/app  │
                                   └────────┬─────────┘
                                            │
                                   ┌────────┴─────────┐
                                   │    rust-gvm      │
                                   │   GMP transport   │
                                   └──────────────────┘
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

Run the compose-backed REST end-to-end tests through the wrapper script:

```bash
./scripts/run-e2e-tests.sh
```

The wrapper waits for `/ready`, prints feed status for diagnostics, then polls the REST resources required by the discovery scan test: discovery scan configs, OpenVAS scanner availability, and usable port lists. This is stricter than feed status alone because gvmd can accept GMP connections before first-boot data imports have populated REST-visible scan configs.

Useful follow-up commands:

```bash
./scripts/compose-dev.sh logs -f gvmd gvm-gateway
./scripts/compose-dev.sh down
```

### Container Runtime Contract

- Default container config: [packaging/gvm-gateway.container.toml](./packaging/gvm-gateway.container.toml)
- Listener: `0.0.0.0:8080`
- Default transport mode: `terminated_by_proxy`
- gvmd socket mount: `/run/gvmd`
- Required backend endpoint: `GVM_GATEWAY_GVMD_ENDPOINT=unix:///run/gvmd/gvmd.sock`
- Required transport-security mode: `GVM_GATEWAY_TRANSPORT_SECURITY_MODE`
- Native TLS certificate path when `GVM_GATEWAY_TRANSPORT_SECURITY_MODE=native`: `GVM_GATEWAY_TLS_CERTIFICATE_PATH`
- Native TLS private-key path when `GVM_GATEWAY_TRANSPORT_SECURITY_MODE=native`: `GVM_GATEWAY_TLS_PRIVATE_KEY_PATH`
- Optional telemetry endpoint: `GVM_GATEWAY_OTLP_ENDPOINT`
- Optional telemetry resource attributes:
  - `GVM_GATEWAY_TELEMETRY_SERVICE_NAME`
  - `GVM_GATEWAY_TELEMETRY_SERVICE_NAMESPACE`
  - `GVM_GATEWAY_TELEMETRY_DEPLOYMENT_ENVIRONMENT`
  - `GVM_GATEWAY_TELEMETRY_SERVICE_INSTANCE_ID`
- Optional shutdown tuning: `GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS`
- Optional REST security overrides:
  - `GVM_GATEWAY_CORS_ALLOWED_ORIGINS`
  - `GVM_GATEWAY_RATE_LIMIT_WINDOW_SECS`
  - `GVM_GATEWAY_RATE_LIMIT_GLOBAL_PER_WINDOW`
  - `GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW`

### Transport Security Contract

- `transport_security_mode = "disabled"` serves plain HTTP intentionally.
- `transport_security_mode = "terminated_by_proxy"` serves plain HTTP behind a trusted TLS-terminating proxy.
- `transport_security_mode = "native"` serves HTTPS directly from the gateway process.
- Native TLS requires both `tls_certificate_path` and `tls_private_key_path`; startup fails if either path is missing or the PEM material cannot be loaded.
- Proxy mode does not require local TLS files.
- Forwarded headers are not trusted implicitly in proxy mode; proxy trust remains an explicit future concern rather than a side effect of enabling proxy termination.

### Telemetry Contract

- Logs are always emitted locally through the gateway tracing subscriber.
- OTLP trace export is enabled only when `otlp_endpoint` or `GVM_GATEWAY_OTLP_ENDPOINT` is set.
- The current exporter path is OTLP over gRPC (for example `http://otel-collector:4317`).
- Stable resource attributes are `service.name`, `service.namespace`, and `service.version`; `deployment.environment` and `service.instance.id` are emitted only when configured.
- Incoming REST requests accept W3C Trace Context headers (`traceparent`, optional `tracestate`, optional `baggage`).
- REST responses return correlation headers for `traceparent` and `tracestate`; `baggage` is consumed for parent context but is not echoed back.
- The gvmd backend runs over GMP on a Unix socket, so trace headers are not forwarded downstream; correlation across the internal boundary is represented by nested gateway/gvmd spans instead.

## Documentation

- [REST API OpenSpec](spec/rest-api/openspec.md)
- [gRPC API OpenSpec](spec/grpc-api/openspec.md)
- [GMP API Proxy Analysis](docs/gmp-api-proxy-analysis.md)
- [Proxy Access Control Analysis](docs/proxy-access-control-analysis.md)
- [MCP Gateway Surface Analysis](docs/mcp-gateway-surface-analysis.md)
- [MCP Implementation Roadmap](docs/mcp-implementation-roadmap.md)

## License

Licensed under [AGPL-3.0-or-later](LICENSE).
