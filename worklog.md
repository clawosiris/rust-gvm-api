# Issue #101: Introduce explicit REST DTOs and remove schema-only duplicates

## Problem

Handlers in the REST adapter return domain models directly (e.g. `Json(target)` where
`target: Target`). OpenAPI schema is maintained through a separate set of `*Doc` types in
`openapi.rs` that duplicate the domain model shape with richer typing (Uuid instead of String,
typed enums instead of strings). This duplication means:

1. Domain model changes can silently drift from the REST contract.
2. Schema types are never used at runtime, so bugs in the schema are invisible until
   the OpenAPI spec test catches them (or doesn't).
3. Adding a new field requires editing both the domain type and the Doc type.

## Approach

Introduce **runtime REST DTOs** that own both the JSON serialization shape and the
JsonSchema/OpenAPI contract. Each handler converts domain -> DTO before returning.
Doc types that are fully replaced by a runtime DTO are removed.

Doc types that intentionally differ from their runtime counterpart (request body schemas
where required fields are modeled as `Option` in the runtime request type for validation,
query parameter schemas, path parameter schemas) are kept.

### Trade-offs

- Adds a thin conversion layer (From impls) between domain and REST. This is intentional:
  the REST adapter should own the wire format.
- Response DTOs use `Uuid` for ID fields and typed enums for string-encoded enums. The
  conversion from domain String -> Uuid uses `parse_str` with a nil-UUID fallback.
- The external REST/OpenAPI contract does not change.

## Implementation Plan

### Step 1: Create `dto.rs` — shared response types

New module `crates/gvm-gateway-rest/src/dto.rs` with:
- `PaginationResponse` (replaces `PaginationDoc`)
- `ResourceRefResponse` (replaces `ResourceRefDoc`)
- `ResourceCreatedResponse` (replaces `ResourceCreatedDoc`)
- `datetime_schema()` helper (moved from `openapi.rs`)
- `parse_uuid()` helper

### Step 2: Add response DTOs to each handler module

For each resource (targets, tasks, reports, results, scan_configs, scanners):
- Define response DTO structs with `#[derive(Serialize, JsonSchema)]`
- Define typed enums where Doc types had them (AliveTest, TaskStatus, etc.)
- Implement `From<DomainType>` for each DTO
- Update handler return expressions to convert domain -> DTO

For sessions:
- Add `JsonSchema` derive to existing `SessionCreatedResponse`, `SessionInfoResponse`
- Add `SessionState` enum, use it in `SessionInfoResponse`
- Make types `pub(crate)` for openapi.rs access

For system endpoints (health, ready, version):
- Add DTOs in `router.rs` with `JsonSchema`

### Step 3: Update `openapi.rs`

- Import runtime DTOs from handler modules
- Replace Doc type references in doc transforms with runtime DTOs
- Remove all Doc types that have been replaced
- Keep: ProblemDetailDoc, path/query Doc types, request body Doc types

### Step 4: Verify

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets`
- `cargo test --workspace`
- OpenAPI contract tests still pass

## Types promoted from Doc to runtime DTO

| Doc type removed | Runtime DTO | Location |
|-----------------|-------------|----------|
| PaginationDoc | PaginationResponse | dto.rs |
| ResourceRefDoc | ResourceRefResponse | dto.rs |
| ResourceCreatedDoc | ResourceCreatedResponse | dto.rs |
| HealthStatusDoc, HealthStateDoc | HealthStatusResponse, HealthState | router.rs |
| ReadinessStatusDoc, ReadinessStateDoc | ReadinessStatusResponse, ReadinessState | router.rs |
| VersionInfoDoc | VersionInfoResponse | router.rs |
| SessionCreatedDoc | SessionCreatedResponse | sessions.rs |
| SessionInfoDoc, SessionStateDoc | SessionInfoResponse, SessionState | sessions.rs |
| TargetDoc | TargetResponse | targets.rs |
| TargetListDoc | TargetListResponse | targets.rs |
| AliveTestDoc | AliveTest | targets.rs |
| TaskDoc | TaskResponse | tasks.rs |
| TaskListDoc | TaskListResponse | tasks.rs |
| TaskStatusDoc | TaskStatus | tasks.rs |
| HostsOrderingDoc | HostsOrdering | tasks.rs |
| TaskActionDoc | TaskActionResponse | tasks.rs |
| ReportDoc | ReportResponse | reports.rs |
| ResultCountDoc | ResultCountResponse | reports.rs |
| ReportListDoc | ReportListResponse | reports.rs |
| ResultDoc | ResultResponse | results.rs |
| NvtRefDoc | NvtRefResponse | results.rs |
| ThreatDoc | Threat | results.rs |
| ResultListDoc | ResultListResponse | results.rs |
| ScanConfigDoc | ScanConfigResponse | scan_configs.rs |
| ScanConfigListDoc | ScanConfigListResponse | scan_configs.rs |
| ScannerDoc | ScannerResponse | scanners.rs |
| ScannerTypeDoc | ScannerType | scanners.rs |
| ScannerListDoc | ScannerListResponse | scanners.rs |

## Doc types kept (no runtime equivalent or intentionally different)

- ProblemDetailDoc
- SessionTokenPathDoc, ResourceIdPathDoc
- TargetListQueryDoc, TaskListQueryDoc, ReportListQueryDoc, GetReportQueryDoc,
  ReportResultsQueryDoc, ResultListQueryDoc, ScanConfigListQueryDoc, ScannerListQueryDoc
- CreateTargetDoc, ModifyTargetDoc, CreateTaskDoc, ModifyTaskDoc,
  CreateScanConfigDoc, ModifyScanConfigDoc

## Risks

- None to REST contract: all schema names, field names, and types remain identical.
- The `From` impls parse String -> Uuid; if a backend ever returns a non-UUID identifier
  the DTO will fall back to the nil UUID. This matches the existing Doc-type assumption.
