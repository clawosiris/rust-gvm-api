# OpenSpec: GVM gRPC API

## 1. Overview

The planned gRPC surface of the `gvm-gateway`, exposing Greenbone Vulnerability Management (GVM) operations over HTTP/2 with Protocol Buffers. It is intended to sit beside REST as a peer incoming adapter over the same shared application core.

> [!IMPORTANT]
> This document is a design target, not a description of the current default workspace build on `main`.
> The authoritative gateway architecture is [docs/gateway-architecture.md](../../docs/gateway-architecture.md).
> REST is implemented today; gRPC remains a planned adapter.

### Goals

- **High performance**: HTTP/2 multiplexing, binary serialization, server-streaming for large responses
- **Type safety**: Protobuf service definitions as the single source of truth for client/server contracts
- **Streaming**: Server-streaming RPCs for reports and scan results (handles GMP large-response challenge)
- **Interoperability**: gRPC reflection + health checking per the standard protocols
- **Observable**: OpenTelemetry traces and structured logging

### Non-Goals

- Browser-friendly API (use the REST API for that)
- Full GMP parity in v0.1 (start with the most-used operations)
- Built-in user management (delegates to gvmd via GMP)

### rust-gvm typed response policy

Service and conversion layers must use structured `rust-gvm` response models.

**Hard requirement:** `rust-gvm-api` must not parse or process raw GMP XML responses directly.
All GMP XML processing and protocol-shape handling belong in `rust-gvm`.

Current mandatory coverage (from `rust-gvm` PR #68):
- task responses (`GetTasksResponse`, `CreateTaskResponse`, `StartTaskResponse` + action aliases)
- report responses (`GetReportsResponse`, `DeleteReportResponse`)
- result responses (`GetResultsResponse`)


## 2. Architecture

The gRPC adapter should follow the shared gateway architecture from [issue #26](https://github.com/greenbone-hive/rust-gvm-api/issues/26): peer incoming adapters over one application core, one domain layer, and one gvmd outgoing adapter.
It should also follow the shared session/connection execution model from [issue #27](https://github.com/greenbone-hive/rust-gvm-api/issues/27): both REST and gRPC resolve session tokens through the same `SessionManager` and the same gvmd connection store.

Current repository status:

- `gvm-gateway-domain`, `gvm-gateway-app`, `gvm-gateway-rest`, `gvm-gateway-gvmd`, and `gvm-gateway` are the active workspace members on `main`.
- gRPC is still deferred from the default build and runtime wiring.
- When implemented, the gRPC adapter should align to the `gvm-gateway-*` crate pattern rather than inventing a separate architecture.

```
Clients
  ├─ REST
  └─ gRPC
         │
         ▼
Incoming adapters
  ├─ gvm-gateway-rest
  └─ gvm-gateway-grpc (planned)
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

### Crate Structure

```text
Target gateway shape for gRPC:

crates/
├── gvm-gateway-domain/   # shared session model, invariants, port traits
├── gvm-gateway-app/      # shared use cases and orchestration
├── gvm-gateway-grpc/     # planned gRPC incoming adapter
├── gvm-gateway-gvmd/     # shared gvmd outgoing adapter
└── gvm-gateway/          # composition root and runtime wiring
```

## 3. Protobuf Service Definitions

### Common Types (`common.proto`)

```protobuf
syntax = "proto3";
package gvm.v1;

message Uuid {
  string value = 1;
}

message Timestamp {
  int64 seconds = 1;
  int32 nanos = 2;
}

message PaginationRequest {
  int32 page = 1;
  int32 per_page = 2;
  string sort_by = 3;
  SortOrder order = 4;
}

enum SortOrder {
  SORT_ORDER_UNSPECIFIED = 0;
  SORT_ORDER_ASC = 1;
  SORT_ORDER_DESC = 2;
}

message PaginationResponse {
  int32 page = 1;
  int32 per_page = 2;
  int32 total = 3;
  int32 total_pages = 4;
}

message FilterExpression {
  string field = 1;
  string operator = 2;  // "eq", "gt", "lt", "gte", "lte", "contains"
  string value = 3;
}
```

### Session Service (`session.proto`)

```protobuf
syntax = "proto3";
package gvm.v1;

service SessionService {
  rpc CreateSession(CreateSessionRequest) returns (CreateSessionResponse);
  rpc GetSession(GetSessionRequest) returns (SessionInfo);
  rpc CloseSession(CloseSessionRequest) returns (CloseSessionResponse);
}

message CreateSessionRequest {
  string username = 1;
  string password = 2;
}

message CreateSessionResponse {
  string session_token = 1;
  int32 expires_in = 2;
  string gmp_version = 3;
}

message GetSessionRequest {
  string session_token = 1;
}

message CloseSessionRequest {
  string session_token = 1;
}

message CloseSessionResponse {}

message SessionInfo {
  string session_token = 1;
  string user = 2;
  SessionState state = 3;
  Timestamp created_at = 4;
  Timestamp last_used_at = 5;
  int32 expires_in = 6;
}

enum SessionState {
  SESSION_STATE_UNSPECIFIED = 0;
  SESSION_STATE_ACTIVE = 1;
  SESSION_STATE_IDLE = 2;
  SESSION_STATE_EXPIRED = 3;
  SESSION_STATE_CLOSED = 4;
}
```

### Target Service (`target.proto`)

```protobuf
syntax = "proto3";
package gvm.v1;

import "gvm/v1/common.proto";

service TargetService {
  rpc ListTargets(ListTargetsRequest) returns (ListTargetsResponse);
  rpc GetTarget(GetTargetRequest) returns (Target);
  rpc CreateTarget(CreateTargetRequest) returns (Target);
  rpc UpdateTarget(UpdateTargetRequest) returns (Target);
  rpc DeleteTarget(DeleteTargetRequest) returns (DeleteTargetResponse);
}

message Target {
  Uuid id = 1;
  string name = 2;
  string comment = 3;
  repeated string hosts = 4;
  repeated string exclude_hosts = 5;
  int32 port_range = 6;
  string port_list_id = 7;
  bool alive_test = 8;
  Timestamp created_at = 9;
  Timestamp modified_at = 10;
}

message ListTargetsRequest {
  PaginationRequest pagination = 1;
  repeated FilterExpression filters = 2;
}

message ListTargetsResponse {
  repeated Target targets = 1;
  PaginationResponse pagination = 2;
}

message GetTargetRequest {
  Uuid id = 1;
}

message CreateTargetRequest {
  string name = 1;
  string comment = 2;
  repeated string hosts = 3;
  repeated string exclude_hosts = 4;
  string port_list_id = 5;
}

message UpdateTargetRequest {
  Uuid id = 1;
  optional string name = 2;
  optional string comment = 3;
  repeated string hosts = 4;
  repeated string exclude_hosts = 5;
}

message DeleteTargetRequest {
  Uuid id = 1;
}

message DeleteTargetResponse {}
```

### Task Service (`task.proto`)

```protobuf
syntax = "proto3";
package gvm.v1;

import "gvm/v1/common.proto";

service TaskService {
  rpc ListTasks(ListTasksRequest) returns (ListTasksResponse);
  rpc GetTask(GetTaskRequest) returns (Task);
  rpc CreateTask(CreateTaskRequest) returns (Task);
  rpc UpdateTask(UpdateTaskRequest) returns (Task);
  rpc DeleteTask(DeleteTaskRequest) returns (DeleteTaskResponse);
  rpc StartTask(StartTaskRequest) returns (StartTaskResponse);
  rpc StopTask(StopTaskRequest) returns (StopTaskResponse);
  rpc ResumeTask(ResumeTaskRequest) returns (ResumeTaskResponse);

  // Server-streaming: subscribe to task status changes
  rpc WatchTaskStatus(WatchTaskStatusRequest) returns (stream TaskStatusEvent);
}

enum TaskStatus {
  TASK_STATUS_UNSPECIFIED = 0;
  TASK_STATUS_NEW = 1;
  TASK_STATUS_REQUESTED = 2;
  TASK_STATUS_RUNNING = 3;
  TASK_STATUS_STOP_REQUESTED = 4;
  TASK_STATUS_STOPPED = 5;
  TASK_STATUS_DONE = 6;
  TASK_STATUS_DELETE_REQUESTED = 7;
}

message Task {
  Uuid id = 1;
  string name = 2;
  string comment = 3;
  Uuid target_id = 4;
  Uuid scan_config_id = 5;
  Uuid scanner_id = 6;
  Uuid schedule_id = 7;
  TaskStatus status = 8;
  int32 progress = 9;      // 0-100
  Uuid last_report_id = 10;
  int32 report_count = 11;
  Timestamp created_at = 12;
  Timestamp modified_at = 13;
}

message StartTaskResponse {
  Uuid report_id = 1;  // ID of the created report
}

message TaskStatusEvent {
  Uuid task_id = 1;
  TaskStatus status = 2;
  int32 progress = 3;
  Timestamp timestamp = 4;
}

// ... (List/Get/Create/Update/Delete requests follow Target pattern)
```

### Report Service (`report.proto`) — Streaming

```protobuf
syntax = "proto3";
package gvm.v1;

import "gvm/v1/common.proto";

service ReportService {
  rpc ListReports(ListReportsRequest) returns (ListReportsResponse);
  rpc GetReport(GetReportRequest) returns (Report);
  rpc DeleteReport(DeleteReportRequest) returns (DeleteReportResponse);

  // Server-streaming: stream results from a large report
  rpc StreamReportResults(StreamReportResultsRequest) returns (stream ReportResult);

  // Server-streaming: export report in chunks
  rpc ExportReport(ExportReportRequest) returns (stream ExportReportChunk);
}

message Report {
  Uuid id = 1;
  Uuid task_id = 2;
  string task_name = 3;
  Timestamp scan_start = 4;
  Timestamp scan_end = 5;
  ResultSummary summary = 6;
  Timestamp created_at = 7;
}

message ResultSummary {
  int32 high = 1;
  int32 medium = 2;
  int32 low = 3;
  int32 info = 4;
  int32 log = 5;
  int32 false_positive = 6;
  int32 total = 7;
}

message ReportResult {
  Uuid id = 1;
  string host = 2;
  int32 port = 3;
  string protocol = 4;
  string nvt_oid = 5;
  string nvt_name = 6;
  float severity = 7;
  string threat = 8;
  string description = 9;
  string solution = 10;
  string solution_type = 11;
}

message StreamReportResultsRequest {
  Uuid report_id = 1;
  float severity_min = 2;  // Optional: filter by minimum severity
}

enum ExportFormat {
  EXPORT_FORMAT_UNSPECIFIED = 0;
  EXPORT_FORMAT_PDF = 1;
  EXPORT_FORMAT_XML = 2;
  EXPORT_FORMAT_CSV = 3;
}

message ExportReportRequest {
  Uuid report_id = 1;
  ExportFormat format = 2;
}

message ExportReportChunk {
  bytes data = 1;
  int64 total_bytes = 2;
}
```

### System Service (`system.proto`)

```protobuf
syntax = "proto3";
package gvm.v1;

service SystemService {
  rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
}

message GetVersionRequest {}
message GetVersionResponse {
  string api_version = 1;
  string gmp_version = 2;
  string server_version = 3;
}

message GetStatusRequest {}
message GetStatusResponse {
  bool gvmd_connected = 1;
  int32 active_connections = 2;
  int64 uptime_seconds = 3;
}
```

## 4. Authentication & Authorization

### 1. Session Token via Metadata

Clients bootstrap a gateway session via `CreateSession`, then pass the opaque session token in gRPC metadata:

```
authorization: Bearer <session-token>
```

The interceptor resolves that token through the shared `SessionManager`, refreshes idle-expiry on successful use, and routes the RPC through the same gvmd-bound backend session model used by REST.

### 2. TLS and Optional mTLS

The repository-wide transport-security contract remains authoritative for the gateway listener:

- `native` for direct TLS termination in the gateway
- `terminated_by_proxy` for a trusted upstream TLS terminator
- `disabled` only where intentional plain HTTP is acceptable for the deployment

If a future gRPC deployment uses service-to-service mTLS, that is an additional transport-layer control rather than the primary application identity model.

### 3. Per-RPC Authorization

```rust
// Interceptor checks permission before handler executes
fn check_permission(user: &User, method: &str) -> Result<(), Status> {
    match method {
        "/gvm.v1.TaskService/StartTask" => require_role(user, Role::User),
        "/gvm.v1.TaskService/DeleteTask" => require_role(user, Role::Admin),
        _ => Ok(()),
    }
}
```

## 5. Error Handling

### GMP → gRPC Status Mapping

| GMP Condition | gRPC Status Code |
|---------------|-----------------|
| Success | `OK` |
| Resource not found | `NOT_FOUND` |
| Authentication failed | `UNAUTHENTICATED` |
| Permission denied | `PERMISSION_DENIED` |
| Invalid request | `INVALID_ARGUMENT` |
| Resource conflict | `ALREADY_EXISTS` |
| GMP connection failure | `UNAVAILABLE` |
| GMP timeout | `DEADLINE_EXCEEDED` |
| Internal error | `INTERNAL` |

### Rich Error Details

Using `google.rpc.Status` with `ErrorInfo`, `BadRequest`, and `DebugInfo` details for structured error information beyond the status code.

## 6. Configuration

The planned gRPC adapter should share the gateway configuration surface with the REST adapter instead of inventing a separate runtime architecture.
The current `main` branch already defines the shared gateway baseline for listener binding, transport-security mode selection, gvmd backend endpoint selection, tracing/export, and shutdown behavior.
gRPC-specific knobs such as reflection, message-size limits, and keepalive policy remain design-time fields until the adapter is wired into the workspace.

```toml
# Illustrative target shape

[server]
bind = "0.0.0.0:8080"
transport_security_mode = "native"    # or "disabled" / "terminated_by_proxy"

[grpc]
reflection_enabled = true
max_message_size_bytes = 67_108_864
keepalive_secs = 60
keepalive_timeout_secs = 20

[gmp]
endpoint = "unix:///run/gvmd/gvmd.sock"
connect_timeout_secs = 5
request_timeout_secs = 60

[sessions]
idle_timeout_secs = 300
max_sessions_global = 1000
max_sessions_per_user = 10
per_session_queue_depth = 32
per_session_queue_timeout_secs = 30

[transport]
mtls_enabled = false
```

## 7. Implementation Phases

### Phase 1: Foundation (MVP)

- Server bootstrap (tonic) integrated into unified `gvm-gateway` binary
- gRPC health checking protocol (`grpc.health.v1`)
- gRPC reflection
- Shared `SessionManager` integration and session lifecycle RPCs
- gvmd connection store keyed by session token
- One in-flight GMP command lane per session with explicit backpressure behavior
- System service (version, status)
- Unified configuration + CLI (shared with REST)
- Structured logging (shared tracing subscriber)

### Phase 2: Core Services

- Target CRUD
- Task CRUD + start/stop/resume
- Report list + get
- Server-streaming for report results (`StreamReportResults`)
- Result list + get
- Protobuf ↔ GMP type conversion layer
- Pagination + filtering

### Phase 3: Auth & Security

- Session-token metadata interceptor
- mTLS support
- Per-RPC authorization
- Rate limiting interceptor
- Audit logging interceptor
- W3C trace-context propagation via metadata where applicable

### Phase 4: Advanced Features

- Task status streaming (`WatchTaskStatus`)
- Report export streaming (`ExportReport`)
- Alerts, Schedules, Scanners, Users, Feeds services
- OpenTelemetry gRPC interceptor

### Phase 5: Production Readiness

- OCI image artifacts runnable under Podman and Docker
- Graceful shutdown with connection draining
- Load balancing considerations (sticky sessions for streams)
- Performance benchmarks vs REST API
- Client SDK generation (Rust, Python, Go)

## 8. Streaming Design

### Why Streaming Matters

GMP report responses can be very large (100k+ results). The raw XML can exceed hundreds of MB. Server-streaming solves this:

1. **Memory**: Server processes results incrementally, never holds full report in memory
2. **Latency**: Client receives first results immediately, doesn't wait for full report
3. **Reliability**: Partial results delivered even if connection drops mid-stream
4. **Backpressure**: HTTP/2 flow control prevents overwhelming slow clients
5. **Consistency**: conversion is driven by `rust-gvm` structured responses; local raw XML parsing is not allowed in rust-gvm-api

### Streaming Flow

```
Client                 gvm-gateway-grpc                 gvmd
  │                            │                            │
  │── StreamReportResults ────►│                            │
  │                            │── get_report/get_results ─►│
  │                            │◄── rust-gvm typed responses │
  │◄── ReportResult #1 ───────│  (convert incrementally)     │
  │◄── ReportResult #2 ───────│                            │
  │◄── ReportResult #3 ───────│                            │
  │◄── ... ───────────────────│                            │
  │◄── (stream complete) ─────│                            │
  │                            │                            │
```

## 9. Dependencies

### Runtime

| Dependency | Purpose |
|------------|---------|
| `gvm-client` / `gvm-gmp` | GMP protocol client + structured response models (tasks/reports/results from rust-gvm PR #68) |
| `tonic` | gRPC framework |
| `prost` | Protobuf serialization |
| `tonic-reflection` | gRPC reflection service |
| `tonic-health` | gRPC health checking |
| `tokio` | Async runtime |
| `tokio-rustls` | Native TLS support when the gateway terminates TLS directly |
| `serde` / `serde_json` | Config serialization |
| `clap` | CLI parsing |
| `tracing` | Structured logging |
| `prometheus` | Metrics |

### Build-Time

| Dependency | Purpose |
|------------|---------|
| `tonic-build` | Protobuf → Rust code generation |

### Dev/Test

| Dependency | Purpose |
|------------|---------|
| `rstest` | Parameterized tests |
| `tonic` (transport feature) | In-process gRPC test client |

## 10. Security Considerations

- **Transport security is explicit**: direct TLS or trusted proxy termination are deployment choices; mTLS remains optional for service-mesh scenarios
- **No credential storage**: bootstrap credentials are used to create a gateway session; opaque session tokens must be treated as bearer secrets and redacted from logs
- **Message size limits**: Configurable max receive size (default 64 MB)
- **Keepalive**: Detect dead connections, prevent resource leaks
- **No unsafe code**: `#[deny(unsafe_code)]` crate-wide
- **Reflection disabled in production**: Configurable, off by default for security

## 11. Client SDK Generation

Protobuf definitions enable automatic client generation:

```bash
# Rust (via tonic-build)
cargo build  # generates Rust client stubs

# Python
python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. proto/gvm/v1/*.proto

# Go
protoc -Iproto --go_out=. --go-grpc_out=. proto/gvm/v1/*.proto
```

## 12. Architectural Decisions

### ADR-001: Unified Gateway Binary (REST + gRPC)

**Status:** Accepted (2026-03-31)

**Context:** We need to decide whether REST and gRPC APIs should be separate binaries or combined.

**Decision:** REST and gRPC should live in the same gateway system and share one application/domain core plus one gvmd adapter boundary. The composition root remains `gvm-gateway`.

**Rationale:**
- **Shared backend boundary**: Both APIs connect to gvmd through the same outgoing adapter shape and should not duplicate GMP integration logic.
- **Shared domain logic**: Authentication, session management, and business validation are identical across protocols.
- **Simpler operations**: One container, one deployment, one set of config files, one health check endpoint.
- **Consistent behavior**: Bug fixes and features apply to both APIs simultaneously.

**Consequences:**
- Binary size may increase once both adapters ship together.
- Both APIs may be deployed together unless a later operational need justifies a different composition.
- Configuration should stay unified at the gateway level even if adapter-specific keys are added.

**Implementation:**

The exact listener topology is intentionally left open here. A shared port, separate ports, or another composition strategy are all acceptable as long as the architectural rule from issue `#26` holds:

- REST and gRPC remain peer incoming adapters.
- Both call into the same application/domain core.
- Both use the same gvmd adapter boundary instead of integrating GMP separately.

---

## 13. Open Questions

- [ ] Bidirectional streaming for interactive scan control?
- [ ] gRPC-Web support for browser clients (via envoy proxy or tonic-web)?
- [ ] Shared-port multiplexing vs separate listeners once the adapter is implemented?
- [ ] Shared protobuf package published as a standalone crate for clients?
