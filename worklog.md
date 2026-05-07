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
