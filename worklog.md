# Phase 2d Work Log — Scan Configs, Scanners, OpenAPI Spec Generation

## Issue

clawosiris/rust-gvm-api#7: feat(rest): Phase 2d — Scan Configs, Scanners, OpenAPI spec generation

## Summary

Added REST endpoints for **scan configuration CRUD** and **scanner read** operations,
with full OpenAPI spec generation and contract validation against the curated YAML specs.

## Changes by Layer

### Domain (`gvm-gateway-domain`)
- Added `ScanConfig`, `ScanConfigPage`, `ScanConfigQuery`, `CreateScanConfigInput`, `ModifyScanConfigInput` types
- Added `Scanner`, `ScannerPage`, `ScannerQuery` types
- Added `ScanConfigPort` trait (list, create, get, modify, delete)
- Added `ScannerPort` trait (list, get)
- Added `scan_config_from_gmp()` and `scanner_from_gmp()` conversion functions

### Application (`gvm-gateway-app`)
- Extended `GatewayService` with `Sc` and `Sn` generic type parameters (with `()` defaults for backward compat)
- Added `with_all()` constructor accepting all 8 port implementations
- Added scan config service methods: `list_scan_configs`, `create_scan_config`, `get_scan_config`, `modify_scan_config`, `delete_scan_config`
- Added scanner service methods: `list_scanners`, `get_scanner`

### REST Adapter (`gvm-gateway-rest`)
- **New:** `scan_configs.rs` — handlers, DTOs, query parsing for scan config CRUD
- **New:** `scanners.rs` — handlers, DTOs, query parsing for scanner reads
- Updated `router.rs` — added routes for `/api/v1/scan-configs`, `/api/v1/scan-configs/{id}`, `/api/v1/scanners`, `/api/v1/scanners/{id}`
- Updated `openapi.rs` — added doc transform functions, schema types, tags, path normalization, query parameter tightening for new endpoints
- Updated all existing handler files to use 8 generic type params (`S, T, K, A, R, Re, Sc, Sn`)

### GMP Adapter (`gvm-gateway-gvmd`)
- `StaticGvmdAdapter` implements `ScanConfigPort` and `ScannerPort` (returns BackendUnavailable)
- `GvmdAdapter` implements `ScanConfigPort` using `gvm_gmp::commands::scan_configs::*`
- `GvmdAdapter` implements `ScannerPort` using `gvm_gmp::commands::scanners::*`

### Main Binary (`gvm-gateway`)
- Updated `main.rs` to use `GatewayService::with_all()` with scan config and scanner adapters

### Acceptance Tests
- Updated `spawn_server()` and `target_harness()` to wire scan config and scanner ports
- Extended OpenAPI contract test to validate scan-configs and scanners paths against curated YAML specs
- Added `DocName::ScanConfigs` and `DocName::Scanners` to the spec comparison infrastructure

## CI Fix (post-PR)

- Ran `cargo fmt --all` to fix formatting across `openapi.rs`, `lib.rs` (app + gvmd), and `acceptance.rs`
- Renamed `ScannerTypeDoc` enum variants from `OpenVAS`/`CVE`/`OSP` to `OpenVas`/`Cve`/`Osp` with `#[serde(rename = "...")]` to satisfy `clippy::upper_case_acronyms` while preserving the serialized OpenAPI contract

## Test Results

All 134 tests pass (0 failures).

## New REST Endpoints

| Method | Path                      | Description                    |
|--------|---------------------------|--------------------------------|
| GET    | /api/v1/scan-configs      | List scan configurations       |
| POST   | /api/v1/scan-configs      | Create a scan configuration    |
| GET    | /api/v1/scan-configs/{id} | Get a scan configuration       |
| PUT    | /api/v1/scan-configs/{id} | Modify a scan configuration    |
| DELETE | /api/v1/scan-configs/{id} | Delete a scan configuration    |
| GET    | /api/v1/scanners          | List scanners                  |
| GET    | /api/v1/scanners/{id}     | Get a scanner                  |
