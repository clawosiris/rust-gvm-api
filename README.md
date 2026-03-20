# rust-gvm-api

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

## Documentation

- [REST API OpenSpec](spec/rest-api/openspec.md)
- [gRPC API OpenSpec](spec/grpc-api/openspec.md)

## License

Licensed under [AGPL-3.0-or-later](LICENSE).
