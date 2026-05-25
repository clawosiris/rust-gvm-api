# rust-gvm-api

[![CI](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/ci.yml)
[![Security](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml/badge.svg)](https://github.com/clawosiris/rust-gvm-api/actions/workflows/security.yml)

> [!NOTE]
> **Releases** are managed via the [release-orchestrator](https://github.com/clawosiris/release-orchestrator).
> To create a nightly/alpha build, create an alpha release in the orchestrator.
> See [RELEASING.md](./RELEASING.md) for details.

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

## Documentation

- [REST API OpenSpec](spec/rest-api/openspec.md)
- [gRPC API OpenSpec](spec/grpc-api/openspec.md)
- [GMP API Proxy Analysis](docs/gmp-api-proxy-analysis.md)
- [Proxy Access Control Analysis](docs/proxy-access-control-analysis.md)
- [MCP Gateway Surface Analysis](docs/mcp-gateway-surface-analysis.md)
- [MCP Implementation Roadmap](docs/mcp-implementation-roadmap.md)

## License

Licensed under [AGPL-3.0-or-later](LICENSE).
