# GMP Ticket Surface Scope

Status: Accepted  
Decision date: 2026-08-03  
Recorded: 2026-08-27

## Context

[`rust-gvm-api` PR #417](https://github.com/greenbone-hive/rust-gvm-api/pull/417)
proposed ticket create, update, and delete operations. Product review rejected
that expansion because GVM tickets are rarely used and the additional public and
protocol surface is not worth its ongoing implementation, compatibility, and test
cost.

The repositories already contain ticket functionality. `rust-gvm-api` exposes
ticket discovery, while `rust-gvm` contains typed ticket command and response
support. This decision records the boundary for future work; it does not remove or
deprecate those existing capabilities.

## Decision

Ticket support is frozen at the currently shipped surface:

- `rust-gvm-api` keeps ticket discovery through `GET /api/v1/tickets` and
  `GET /api/v1/tickets/{id}`.
- `rust-gvm-api` will not add ticket create, clone, update, or delete operations to
  REST, gRPC, MCP, CLI, or another public adapter.
- `rust-gvm` keeps its existing ticket command builders, response models, typed
  client integration, and mock behavior, but will not expand them with new
  ticket-specific commands, fields, helpers, mock behavior, or conformance work.
- Correctness, security, compatibility, documentation, and test maintenance for
  the existing surface remain in scope.
- Lower-level raw GMP request paths remain available under their existing
  forward-compatibility contract; they do not create a supported ticket-specific
  API commitment.

Coverage audits and parity plans must treat additional GMP ticket functionality as
a deliberate exclusion rather than an implementation gap.

## Reconsideration

Expanding this surface requires a new explicit product decision backed by a
concrete consumer need and an identified maintenance owner. Protocol availability
or parity with another GMP client is not sufficient by itself.

## Consequences

- [`rust-gvm-api` issue #393](https://github.com/greenbone-hive/rust-gvm-api/issues/393)
  is not planned.
- Future GMP schema-drift audits may report ticket additions, but those additions
  do not become rust-gvm or gateway roadmap items automatically.
- Integrations that manage tickets in an external system should continue using
  that system's API directly; the repository's OTOBO example already follows this
  boundary.
