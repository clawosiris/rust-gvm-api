# Refactor: Remove Per-Resource Generic Sprawl from Gateway State

## Issue

clawosiris/rust-gvm-api#95: refactor(architecture): remove per-resource generic sprawl from gateway state

Stacked on top of PR #94 (`feat/phase-2d-scan-configs-scanners`), which introduced `Sc`/`Sn` type params
and made the 8-generic-parameter sprawl painfully visible.

## Problem

`GatewayService<S, T, K, A, R, Re, Sc, Sn>` carries 8 generic type parameters that propagate
through every handler function, router helper, and test constructor. Each new resource requires
touching every existing handler's generic signature even when that handler doesn't use the new port.
This violates the open/closed principle: adding a resource should not require modifying unrelated handlers.

## Approach: Trait-Object Erasure (Dynamic Dispatch)

Replace the 8 generic type parameters with `Arc<dyn XxxPort>` trait objects inside `GatewayService`.
This makes `GatewayService` a concrete type, so handlers, routers, and tests no longer carry or
propagate generics.

**Trade-offs:**
- Adds one vtable indirection per port call (negligible for network-bound I/O).
- Slightly more allocation at construction time (already using Arc, so no new heap allocs).
- Static dispatch can be reintroduced later via a `GatewayServiceTyped<S, T, ...>` if profiling demands it.
- Trait-object service boundary is reusable by a future gRPC adapter (same `GatewayService` value).

**Why not a registry/map approach:**
Trait objects are idiomatic Rust for this pattern, preserve type safety at the port boundary, and
keep the API surface identical. A `HashMap<TypeId, Box<dyn Any>>` would lose compile-time guarantees.

## Implementation Plan

### Step 1: Make `GatewayService` concrete (gvm-gateway-app)

- Remove all generic type parameters from `GatewayService`.
- Store each port as `Arc<dyn XxxPort>` (e.g. `system: Arc<dyn SystemPort>`).
- Replace `new()` and `with_all()` constructors to accept `Arc<dyn XxxPort>` arguments.
- Merge the three separate `impl` blocks (split by different trait bounds) into one.
- Derive `Clone` manually since all fields are `Arc`.
- Update all unit tests — mock types stay the same, but construction uses `Arc::new(mock) as Arc<dyn XxxPort>`.

### Step 2: Remove generics from REST handlers (gvm-gateway-rest)

- In `router.rs`: remove `<S, T, K, A, R, Re, Sc, Sn>` from `build_router`, `build_openapi`,
  `documented_router`, `health`, `ready`, `version`. Accept/return concrete `GatewayService`.
- In each handler module (`targets.rs`, `tasks.rs`, `reports.rs`, `results.rs`, `scan_configs.rs`,
  `scanners.rs`, `sessions.rs`): remove all generic type parameters and trait bounds from every
  handler function. Use `State(service): State<GatewayService>`.

### Step 3: Update binary entrypoint (gvm-gateway)

- In `main.rs`: remove turbofish annotations, use `Arc::new(adapter) as Arc<dyn XxxPort>` at
  construction site.

### Step 4: Update tests

- Unit tests in `gvm-gateway-app`: update `create_test_service()` to construct concrete `GatewayService`.
- Acceptance/integration tests: update any test harness constructors.

### Step 5: Verify

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets`
- `cargo test --workspace`
- `cargo build --workspace`

## Files Changed

| File | Change |
|------|--------|
| `crates/gvm-gateway-app/src/lib.rs` | Remove generics from `GatewayService`, merge impl blocks |
| `crates/gvm-gateway-rest/src/router.rs` | Remove generics from router + utility handlers |
| `crates/gvm-gateway-rest/src/targets.rs` | Remove generics from 5 handler fns |
| `crates/gvm-gateway-rest/src/tasks.rs` | Remove generics from 8 handler fns |
| `crates/gvm-gateway-rest/src/reports.rs` | Remove generics from 4 handler fns |
| `crates/gvm-gateway-rest/src/results.rs` | Remove generics from 2 handler fns |
| `crates/gvm-gateway-rest/src/scan_configs.rs` | Remove generics from 5 handler fns |
| `crates/gvm-gateway-rest/src/scanners.rs` | Remove generics from 2 handler fns |
| `crates/gvm-gateway-rest/src/sessions.rs` | Remove generics from 3 handler fns |
| `crates/gvm-gateway/src/main.rs` | Simplify construction |

---

# Issue #96: Make REST and GMP adapters speak through domain-owned boundaries

## Problem

The domain crate (`gvm-gateway-domain`) depends on `gvm-gmp` and contains
`*_from_gmp()` conversion functions that take `gvm_gmp::responses::*` types
as parameters. This violates the hexagonal architecture rule that the domain
layer must know nothing about GMP or GVMD protocol types.

### Boundary violations found

1. **`gvm-gateway-domain/Cargo.toml`** lists `gvm-gmp` as a dependency.
2. **`gvm-gateway-domain/src/lib.rs`** defines six public conversion functions
   (`target_from_gmp`, `task_from_gmp`, `report_from_gmp`, `result_from_gmp`,
   `scan_config_from_gmp`, `scanner_from_gmp`) whose parameter types come from
   `gvm_gmp::responses`.
3. **`gvm-gateway/tests/acceptance.rs`** imports `target_from_gmp` from domain
   and `GetTargetsResponse` from `gvm_gmp::responses` directly.

### What is already correct

- Port traits (in domain) accept/return only domain types.
- `gvm-gateway-app` depends only on domain types.
- `gvm-gateway-rest` does not import `gvm-gmp` at all.
- `gvm-gateway-gvmd` already does all GMP command building internally.

## Plan

### Step 1 — Move conversion functions to gvmd adapter

Move the six `*_from_gmp()` functions from `gvm-gateway-domain/src/lib.rs`
to `gvm-gateway-gvmd/src/lib.rs`. They already belong there since the gvmd
crate is the only consumer.

### Step 2 — Remove gvm-gmp dependency from domain

Remove `gvm-gmp` from `gvm-gateway-domain/Cargo.toml`. Move `serde_json` to
`[dev-dependencies]` since it is only used in `#[cfg(test)]` blocks.

### Step 3 — Update gvmd adapter imports

Change imports in `gvm-gateway-gvmd/src/lib.rs` from
`gvm_gateway_domain::{target_from_gmp, ...}` to local function references.

### Step 4 — Update acceptance tests

In `gvm-gateway/tests/acceptance.rs`, change the `target_from_gmp` import
from `gvm_gateway_domain` to `gvm_gateway_gvmd`.

### Step 5 — Add architectural boundary test

Add a compile-time or test-time check that enforces:
- `gvm-gateway-domain` does NOT depend on `gvm-gmp`, `gvm-client`, or
  `gvm-connection`.
- `gvm-gateway-app` does NOT depend on `gvm-gmp`, `gvm-client`, or
  `gvm-connection`.
- `gvm-gateway-rest` does NOT depend on `gvm-gmp`, `gvm-client`, or
  `gvm-connection`.

This will be implemented as a test that parses Cargo.toml files and asserts
the absence of banned dependencies.

### Step 6 — Verify

- `cargo check` passes.
- `cargo test --workspace` passes.
- `cargo clippy --workspace` passes.
- OpenAPI contract tests still pass (REST contract is unchanged).

## Risks

- None to REST contract: no handler, DTO, or route changes.
- The gvmd adapter's public API grows by six `pub fn` conversions, but these
  are only consumed by the composition-root acceptance tests.
