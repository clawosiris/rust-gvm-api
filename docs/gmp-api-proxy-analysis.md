# GMP API Proxy Analysis

## 1. Scope

This document explains how `rust-gvm-api` should expose a gateway in front of `gvmd`.

The backend execution path remains:

`rust-gvm-api -> rust-gvm -> GMP/XML -> gvmd`

This analysis focuses on the public gateway surfaces that sit above that execution layer.

## 2. Why a Gateway Exists

`gvmd` exposes GMP as a raw XML stream over a persistent Unix socket or TLS connection. It does not offer a native REST or gRPC surface.

That creates a clear gateway opportunity for consumers that want:

- standard API contracts
- typed client generation
- browser and script-friendly access
- simpler integration than raw GMP XML
- agent-facing tool access without re-implementing GMP session handling

## 3. Gateway Built on `rust-gvm`

Rather than waiting for `gvmd` itself to grow new public surfaces, the project can build them on top of `rust-gvm`:

- `rust-gvm-api` owns the customer-facing gateway surfaces
- `rust-gvm` stays the execution substrate for transport, protocol, parsing, and typed GMP builders

```text
┌──────────────┐   REST / gRPC            ┌──────────────────┐      GMP/XML       ┌────────┐
│ Web UI       │◄────────────────────────►│   rust-gvm-api   │◄──────────────────►│ gvmd   │
│ Scripts      │ HTTP/JSON and            │  gateway layer   │                    │        │
│ Automation   │ Protobuf                 │                  │                    │        │
│ Agents       │                          │                  │                    │        │
└──────────────┘                          └────────┬─────────┘                    └────────┘
                                                   │
                                            ┌──────┴──────┐
                                            │  rust-gvm   │
                                            │ execution   │
                                            │ substrate   │
                                            └─────────────┘
```

The gateway stays relatively thin if all public surfaces share one execution core:

1. Accept REST or gRPC requests.
2. Map them into one canonical operation catalog.
3. Execute them through `rust-gvm`.
4. Normalize the result into the calling surface.

## 4. Frontend Options

### Option A: REST/JSON

REST is the easiest surface for human-operated tooling, browser flows, `curl`, and lightweight automation.

Typical characteristics:

- `axum` or similar HTTP framework
- OpenAPI-backed contracts
- token-based gateway sessions
- predictable request/response semantics

### Option B: gRPC

gRPC is the strongest fit for:

- typed service-to-service integrations
- generated clients
- streaming-heavy operations such as large reports

It brings more schema work up front, but gives the cleanest typed machine interface once the core contracts settle.

### Option C: Hybrid REST + gRPC

This is the intended long-term shape:

- `REST` for browser/script-friendly access
- `gRPC` for typed service integration and streaming workloads

Agent- and tool-driven workflows are served outside this repository by the standalone [openvas-mcp-server](https://github.com/clawosiris/openvas-mcp-server), which consumes the REST API as a regular client.

## 5. Recommended Gateway Architecture

The gateway should have four layers:

1. REST adapter
2. gRPC adapter
3. shared application core
4. `rust-gvm` execution layer

The shared core owns:

- canonical operation ids
- request validation
- auth/session handling
- policy enforcement hooks
- endpoint routing
- error normalization
- audit events

## 6. Session and Connection Model

This design is constrained by how `gvmd` behaves:

- backend connections carry authentication state
- work must be serialized per authenticated backend session where required
- idle/revoked sessions need cleanup

That means the gateway should expose an explicit session bootstrap flow:

1. client authenticates to the gateway
2. gateway opens/authenticates the `gvmd` session through `rust-gvm`
3. gateway returns a session token
4. subsequent REST/gRPC operations reuse that gateway session

This model should be shared across all public surfaces.

## 7. Recommended Delivery Order

The safest sequence is:

1. define the canonical operation catalog
2. stand up the shared gateway core
3. ship a narrow `REST` slice first
4. expand parity across higher-value domains
5. add or expand `gRPC` once the contracts are stable

## 8. Practical Consequences

For downstream consumers:

| Consumer | Preferred gateway shape |
| --- | --- |
| browser/admin tools | REST |
| service integrations | gRPC or REST |
| agent/tool workflows | the standalone [openvas-mcp-server](https://github.com/clawosiris/openvas-mcp-server) consuming the REST API |

For project boundaries:

- `rust-gvm-api` owns public gateway surfaces and their contracts
- `rust-gvm` owns the backend execution substrate

## 9. Summary

The gateway is one shared core with two peer adapters:

- REST
- gRPC

That preserves a clean repo boundary and keeps customer-facing behavior in the API-layer repo. Agent-facing tooling consumes the REST contract from its own repository.
