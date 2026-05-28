# Gateway Architecture

This document is the repository-local architecture reference for `rust-gvm-api`.
It reflects the design intent captured in [issue #26](https://github.com/clawosiris/rust-gvm-api/issues/26) and the current repository shape on `main`.

## Core Rules

- The gateway follows a ports-and-adapters (hexagonal) architecture.
- `rust-gvm-api` must not parse raw GMP XML directly.
  All GMP XML parsing and protocol-shape handling belong in `rust-gvm`; the gateway consumes typed models and protocol APIs from `rust-gvm`.
- REST, gRPC, and future MCP are peer incoming adapters over one shared execution core.
- The domain layer owns session lifecycle rules and invariants, but does not hold live I/O handles.
- The gvmd outgoing adapter owns live backend connections, session-bound command serialization, and transport concerns.
- The current deployment target is a single gateway instance with in-memory session and connection state.
- Transport security must be explicit: plain HTTP (`disabled`), proxy-terminated HTTP (`terminated_by_proxy`), or native HTTPS (`native`).
- Trace correlation uses OpenTelemetry plus W3C Trace Context at the public adapter boundary.

## Current Workspace Shape

The authoritative workspace members are defined in the root `Cargo.toml`:

```text
crates/gvm-gateway-domain
crates/gvm-gateway-app
crates/gvm-gateway-rest
crates/gvm-gateway-gvmd
crates/gvm-gateway
```

Their responsibilities are:

- `gvm-gateway-domain`: session entities, lifecycle/state rules, port traits, domain errors.
- `gvm-gateway-app`: shared use cases and orchestration over the domain and ports.
- `gvm-gateway-rest`: REST incoming adapter, HTTP translation, security middleware, request/response mapping.
- `gvm-gateway-gvmd`: gvmd outgoing adapter built on `rust-gvm`.
- `gvm-gateway`: composition root, config loading, listener/bootstrap, tracing init, shutdown wiring.

## Adapter Status

- REST is the implemented public adapter on `main`.
- gRPC remains a planned adapter and contract surface; its spec should align to this architecture, but it is not wired into the default workspace build today.
- MCP is planned as another peer adapter over the same application core; it is not yet implemented.

## High-Level Structure

```text
Clients
  ├─ REST
  ├─ gRPC (planned)
  └─ MCP  (planned)
         │
         ▼
Incoming adapters
  ├─ gvm-gateway-rest
  ├─ gvm-gateway-grpc (planned)
  └─ gvm-gateway-mcp  (planned)
         │
         ▼
Application core
  └─ gvm-gateway-app
         │
         ▼
Domain
  └─ gvm-gateway-domain
         │
         ▼
Outgoing adapter
  └─ gvm-gateway-gvmd
         │
         ▼
rust-gvm -> gvmd
```

## Session and Backend Ownership

- Incoming adapters authenticate/translate requests but do not own backend sessions.
- The domain layer owns session identity, limits, expiry, and lifecycle decisions.
- The gvmd adapter owns authenticated backend connections and per-session execution serialization.
- Shared use cases in `gvm-gateway-app` coordinate those responsibilities without leaking transport/framework concerns into the domain.

## Development Implications

- Architecture discussions and new adapter work should update this document together with issue `#26` when the design changes materially.
- Specs under `spec/rest-api/` and `spec/grpc-api/` should treat this document as the architectural source of truth.
- Repo docs must distinguish clearly between:
  - implemented gateway surfaces on `main`
  - planned adapter surfaces
  - exploratory or legacy artifacts that are not part of the current workspace composition root
