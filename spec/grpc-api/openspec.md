# OpenSpec: GVM gRPC API (`gvm-grpc-api`)

## 1. Overview

A gRPC API server that exposes Greenbone Vulnerability Management (GVM) operations over HTTP/2 with Protocol Buffers. Built on [tonic](https://github.com/hyperium/tonic) and [rust-gvm](https://github.com/clawosiris/rust-gvm), optimized for high-throughput, streaming, and service-to-service communication.

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

The gRPC API is part of the unified `gvm-gateway` binary (see [ADR-001](#adr-001-unified-gateway-binary-rest--grpc)).

Both REST and gRPC are served on **a single port** (`:8080`) using HTTP/2 content-type multiplexing.

```
┌──────────────────────────────────────────────────────────────────────┐
│                      gvm-gateway (:8080)                              │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                   Protocol Multiplexer                        │    │
│  │         (routes by Content-Type: application/grpc)            │    │
│  └──────────────────────────┬───────────────────────────────────┘    │
│                             │                                         │
│            ┌────────────────┴────────────────┐                       │
│            │                                  │                       │
│  ┌─────────┴─────────┐              ┌────────┴────────┐              │
│  │   REST (Axum)     │              │   gRPC (Tonic)  │              │
│  │  ┌─────────────┐  │              │  ┌────────────┐ │              │
│  │  │ Middleware  │  │              │  │Interceptors│ │              │
│  │  │(Auth/Trace) │  │              │  │(Auth/Trace)│ │              │
│  │  └──────┬──────┘  │              │  └─────┬──────┘ │              │
│  │  ┌──────┴──────┐  │              │  ┌─────┴──────┐ │              │
│  │  │  Handlers   │  │              │  │  Services  │ │              │
│  │  │(targets,...)│  │              │  │(Target,...)│ │              │
│  │  └──────┬──────┘  │              │  └─────┬──────┘ │              │
│  └─────────┼─────────┘              └────────┼────────┘              │
│                 │                                 │                   │
│                 └─────────────┬─────────────────-─┘                   │
│                               │                                       │
│                 ┌─────────────┴─────────────┐                         │
│                 │     Shared Domain Layer    │                         │
│                 │  (gvm-gateway-domain)      │                         │
│                 └─────────────┬─────────────┘                         │
│                               │                                       │
│                 ┌─────────────┴─────────────┐                         │
│                 │    GMP Connection Pool     │                         │
│                 │  (gvm-gateway-gvmd)        │                         │
│                 └─────────────┬─────────────┘                         │
└───────────────────────────────┼───────────────────────────────────────┘
                                │ GMP/XML
                          ┌─────┴─────┐
                          │   gvmd    │
                          └───────────┘
```

### Crate Structure

```
crates/gvm-grpc-api/
├── proto/
│   └── gvm/
│       └── v1/
│           ├── common.proto       # Shared types (UUID, Timestamp, Pagination)
│           ├── target.proto       # Target service
│           ├── task.proto         # Task service
│           ├── report.proto       # Report service (with streaming)
│           ├── result.proto       # Result service
│           ├── scan_config.proto  # Scan config service
│           ├── scanner.proto      # Scanner service
│           ├── alert.proto        # Alert service
│           ├── schedule.proto     # Schedule service
│           ├── user.proto         # User service
│           ├── feed.proto         # Feed service
│           └── system.proto       # Version, health
├── src/
│   ├── main.rs          # Entry point, server bootstrap
│   ├── lib.rs           # Library root
│   ├── config.rs        # CLI args + config file loading
│   ├── error.rs         # GMP errors → gRPC status mapping
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs       # JWT from metadata
│   │   └── mtls.rs      # Mutual TLS client cert auth
│   ├── interceptors/
│   │   ├── mod.rs
│   │   ├── auth.rs      # Auth interceptor
│   │   ├── rate_limit.rs
│   │   ├── audit.rs
│   ├── services/
│   │   ├── mod.rs
│   │   ├── target.rs
│   │   ├── task.rs
│   │   ├── report.rs    # Server-streaming for large reports
│   │   ├── result.rs
│   │   ├── scan_config.rs
│   │   ├── scanner.rs
│   │   ├── alert.rs
│   │   ├── schedule.rs
│   │   ├── user.rs
│   │   ├── feed.rs
│   │   └── system.rs
│   ├── convert/
│   │   ├── mod.rs       # GMP types ↔ Protobuf message conversion
│   │   ├── target.rs
│   │   ├── task.rs
│   │   ├── report.rs
│   │   └── result.rs
│   └── pool.rs          # GMP connection pool
├── build.rs             # tonic-build protobuf compilation
├── tests/
│   ├── services/        # Integration tests per service
│   └── fixtures/        # Test data
└── Cargo.toml
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

### 1. JWT via Metadata

Clients pass JWT tokens in gRPC metadata:

```
authorization: Bearer <jwt-token>
```

Auth interceptor validates the token and extracts user identity before the RPC handler.

### 2. Mutual TLS (mTLS)

For service-to-service communication:
- Server presents its certificate
- Client presents its certificate
- Server validates client cert against a trusted CA
- Client identity extracted from certificate CN/SAN

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

The gRPC API shares a unified configuration file with the REST API (see [ADR-001](#adr-001-unified-gateway-binary-rest--grpc)).

```toml
# gvm-gateway.toml

[server]
bind = "0.0.0.0:8080"                 # Single port for REST + gRPC
max_message_size_bytes = 67_108_864   # 64 MB (for large gRPC responses)
keepalive_secs = 60
keepalive_timeout_secs = 20

[grpc]
reflection_enabled = true             # gRPC reflection for grpcurl/grpcui (disable in prod)

[tls]
cert = "/etc/gvm-gateway/tls/cert.pem"
key = "/etc/gvm-gateway/tls/key.pem"
ca = "/etc/gvm-gateway/tls/ca.pem"    # For mTLS client verification (optional)

[gmp]
transport = "unix"
socket_path = "/run/gvmd/gvmd.sock"
pool_size = 10
connect_timeout_secs = 5
request_timeout_secs = 60

[auth]
jwt_secret = "${JWT_SECRET}"
jwt_expiration_secs = 3600
mtls_enabled = false

[rate_limit]
default_rps = 500
burst = 750

[logging]
format = "json"
level = "info"

[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "gvm-gateway"
```

## 7. Implementation Phases

### Phase 1: Foundation (MVP)

- Server bootstrap (tonic) integrated into unified `gvm-gateway` binary
- gRPC health checking protocol (`grpc.health.v1`)
- gRPC reflection
- GMP connection pool (shared with REST API)
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

- JWT interceptor
- mTLS support
- Per-RPC authorization
- Rate limiting interceptor
- Audit logging interceptor
- Request ID propagation via metadata

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
Client                    gvm-grpc-api                    gvmd
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
| `serde` / `serde_json` | Config serialization |
| `jsonwebtoken` | JWT handling |
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

- **TLS by default**: All gRPC traffic encrypted; mTLS optional for service mesh
- **No credential storage**: JWT secret from env, GMP credentials per-session
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

**Decision:** REST and gRPC will be served from a **single binary** (`gvm-gateway`) on separate ports.

**Rationale:**
- **Shared connection pool**: Both APIs connect to gvmd via GMP. A single pool reduces connection overhead and simplifies resource management.
- **Shared domain logic**: Authentication, session management, and business validation are identical across protocols.
- **Simpler operations**: One container, one deployment, one set of config files, one health check endpoint.
- **Consistent behavior**: Bug fixes and features apply to both APIs simultaneously.

**Consequences:**
- Binary size increases slightly (includes both Axum and Tonic dependencies)
- Both APIs must be deployed together (cannot scale independently)
- Configuration covers both protocols in a single file
- Single port simplifies firewall rules and load balancer config

**Implementation:**

Both protocols are served on a single port using HTTP/2 content-type multiplexing. The server inspects the `Content-Type` header to route requests:
- `application/grpc` → gRPC handler (Tonic)
- All other requests → REST handler (Axum)

```rust
// gvm-gateway/src/main.rs
use hyper::Request;
use tonic::body::BoxBody;
use tower::ServiceExt;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load()?;
    let gmp_pool = GmpPool::new(&config.gmp).await?;
    
    let rest = rest_router(gmp_pool.clone());
    let grpc = grpc_server(gmp_pool.clone());
    
    // Multiplex based on content-type
    let service = tower::service_fn(move |req: Request<_>| {
        let rest = rest.clone();
        let grpc = grpc.clone();
        async move {
            if is_grpc_request(&req) {
                grpc.oneshot(req).await
            } else {
                rest.oneshot(req).await
            }
        }
    });
    
    axum::Server::bind(&config.bind)
        .serve(service.into_make_service())
        .await?;
    Ok(())
}

fn is_grpc_request<B>(req: &Request<B>) -> bool {
    req.headers()
        .get("content-type")
        .map(|v| v.as_bytes().starts_with(b"application/grpc"))
        .unwrap_or(false)
}
```

**Default port:** `8080` (HTTP/2, serves both REST and gRPC)

---

## 13. Open Questions

- [ ] Bidirectional streaming for interactive scan control?
- [ ] gRPC-Web support for browser clients (via envoy proxy or tonic-web)?
- [ ] Shared protobuf package published as a standalone crate for clients?
