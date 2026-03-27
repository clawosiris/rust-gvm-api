# Test Spec: GVM gRPC API (`gvm-grpc-api`)

## 1. Test Strategy

### Test Pyramid

```
         ┌──────────┐
         │   E2E    │  Against real gvmd (Docker Compose)
        ┌┴──────────┴┐
        │ Integration │  In-process tonic test client + mock GMP
       ┌┴────────────┴┐
       │    Unit       │  Individual functions, no I/O
      └────────────────┘
```

### Test Categories

| Category | Scope | Dependencies | Speed |
|----------|-------|-------------|-------|
| Unit | Conversions, validation, interceptor logic | None | < 1s each |
| Integration | Full RPC calls with mock GMP pool | tonic in-process transport | < 5s each |
| E2E | Full server against gvmd | Docker Compose stack | < 30s each |
| Contract | Protobuf backward compatibility | `buf breaking` | < 2s |
| Streaming | Server-streaming correctness + backpressure | Mock large reports | < 10s each |

## 2. Unit Tests

### 2.1 Error Mapping (`error.rs`)

| Test | Input | Expected |
|------|-------|----------|
| `gmp_not_found_maps_to_not_found` | GMP "resource not found" | `Status::not_found()` |
| `gmp_auth_failure_maps_to_unauthenticated` | GMP "authentication failed" | `Status::unauthenticated()` |
| `gmp_permission_denied_maps_to_permission_denied` | GMP "permission denied" | `Status::permission_denied()` |
| `gmp_connection_failure_maps_to_unavailable` | GMP connection error | `Status::unavailable()` |
| `gmp_timeout_maps_to_deadline_exceeded` | GMP timeout | `Status::deadline_exceeded()` |
| `error_includes_details` | Any error | Status message is descriptive, not generic |

### 2.2 Protobuf ↔ GMP Conversion (`convert/`)

| Test | Scope |
|------|-------|
| `target_gmp_to_proto_roundtrip` | GMP Target → Proto Target → verify all fields |
| `target_proto_to_gmp_create` | CreateTargetRequest → GMP create_target args |
| `task_status_all_variants` | Every GMP status string → TaskStatus enum |
| `task_from_structured_response` | gRPC task conversion consumes rust-gvm structured task responses |
| `report_result_severity_precision` | Float severity preserved (no truncation) |
| `report_and_result_from_structured_response` | gRPC report/result conversion consumes rust-gvm structured responses |
| `timestamp_conversion` | GMP ISO timestamp → Proto Timestamp (seconds + nanos) |
| `uuid_conversion` | String UUID → Proto Uuid → back to string |
| `empty_optional_fields` | Missing GMP fields → Proto default values (not panic) |
| `unknown_status_string` | Unrecognized GMP status → `UNSPECIFIED` |

### 2.3 Authentication (`auth/`)

| Test | Scope |
|------|-------|
| `jwt_from_metadata_valid` | `authorization: Bearer <token>` → claims |
| `jwt_from_metadata_missing` | No authorization metadata → UNAUTHENTICATED |
| `jwt_from_metadata_malformed` | `authorization: NotBearer xxx` → UNAUTHENTICATED |
| `jwt_expired` | Expired token → UNAUTHENTICATED |
| `jwt_wrong_signature` | Wrong secret → UNAUTHENTICATED |
| `mtls_client_cert_extracted` | Valid client cert → identity from CN |
| `mtls_untrusted_cert_rejected` | Unknown CA → UNAUTHENTICATED |

### 2.4 Interceptors

| Test | Scope |
|------|-------|
| `rate_limit_under_threshold_passes` | N requests < limit → all OK |
| `rate_limit_over_threshold_rejects` | N requests > limit → RESOURCE_EXHAUSTED |
| `audit_log_captures_method` | RPC call → audit log entry with method name |
| `audit_log_captures_user` | Authenticated call → log entry with user ID |

### 2.5 Pagination

| Test | Scope |
|------|-------|
| `pagination_defaults` | Empty PaginationRequest → page=1, per_page=25 |
| `pagination_max_per_page` | per_page=5000 → clamped to 1000 |
| `pagination_response_total_pages` | total=142, per_page=25 → total_pages=6 |
| `pagination_to_gmp_filter` | page=3, per_page=50 → GMP `first=100 rows=50` |

### 2.6 Filter Expression

| Test | Scope |
|------|-------|
| `filter_eq_to_gmp` | `{field: "name", operator: "eq", value: "test"}` → GMP `name=test` |
| `filter_severity_gt` | `{field: "severity", operator: "gt", value: "7.0"}` → GMP filter |
| `multiple_filters_combined` | 3 filters → combined GMP expression with `and` |
| `empty_filters_no_constraint` | No filters → no GMP filter string |

## 3. Integration Tests

### 3.1 Test Infrastructure

```rust
// tests/common/mod.rs
use tonic::transport::{Channel, Server};
use tokio::net::TcpListener;

/// Starts an in-process gRPC server with mock GMP pool.
async fn test_server() -> (Channel, tokio::task::JoinHandle<()>) {
    let mock_pool = MockGmpPool::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(TargetServiceServer::new(TargetServiceImpl::new(mock_pool.clone())))
            .add_service(TaskServiceServer::new(TaskServiceImpl::new(mock_pool.clone())))
            .add_service(ReportServiceServer::new(ReportServiceImpl::new(mock_pool)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    (channel, handle)
}
```

### 3.2 Health & Reflection

| Test | RPC | Expected |
|------|-----|----------|
| `health_check_serving` | `grpc.health.v1/Check` | `SERVING` |
| `health_check_not_serving` | `grpc.health.v1/Check` (GMP down) | `NOT_SERVING` |
| `reflection_lists_services` | gRPC reflection | All services listed |
| `get_version` | `SystemService/GetVersion` | Returns API + GMP versions |

### 3.3 Target Service

| Test | RPC | Setup | Expected |
|------|-----|-------|----------|
| `list_targets_empty` | `ListTargets({})` | No targets in mock | OK, empty list |
| `list_targets_paginated` | `ListTargets({page: 2, per_page: 10})` | 25 targets | 10 targets, correct pagination |
| `create_target` | `CreateTarget({name, hosts})` | — | OK, target with ID |
| `create_target_missing_name` | `CreateTarget({})` | — | INVALID_ARGUMENT |
| `get_target` | `GetTarget({id})` | Target exists | OK, full target |
| `get_target_not_found` | `GetTarget({bad_id})` | — | NOT_FOUND |
| `update_target` | `UpdateTarget({id, name})` | Target exists | OK, updated |
| `delete_target` | `DeleteTarget({id})` | Target exists | OK |

### 3.4 Task Service

| Test | RPC | Setup | Expected |
|------|-----|-------|----------|
| `create_task` | `CreateTask({...})` | Target + config exist | OK |
| `start_task` | `StartTask({id})` | Task exists | OK, report_id |
| `stop_running_task` | `StopTask({id})` | Task running | OK |
| `stop_idle_task` | `StopTask({id})` | Task not running | FAILED_PRECONDITION |
| `resume_stopped_task` | `ResumeTask({id})` | Task stopped | OK |

### 3.5 Report Service — Streaming

| Test | RPC | Setup | Expected |
|------|-----|-------|----------|
| `stream_results_all` | `StreamReportResults({id})` | Report with 100 results | 100 messages received |
| `stream_results_severity_filter` | `StreamReportResults({id, severity_min: 7.0})` | Mixed severities | Only high/critical results |
| `stream_results_empty_report` | `StreamReportResults({id})` | Empty report | Stream completes immediately |
| `stream_results_not_found` | `StreamReportResults({bad_id})` | — | NOT_FOUND |
| `stream_large_report` | `StreamReportResults({id})` | 50k results | All received, memory bounded |
| `export_report_pdf` | `ExportReport({id, PDF})` | Report exists | Chunked PDF bytes |
| `export_report_csv` | `ExportReport({id, CSV})` | Report exists | Chunked CSV bytes |

### 3.6 Task Status Watch — Streaming

| Test | RPC | Setup | Expected |
|------|-----|-------|----------|
| `watch_task_receives_updates` | `WatchTaskStatus({id})` | Task transitions | Status events in order |
| `watch_task_completes_on_done` | `WatchTaskStatus({id})` | Task finishes | Stream ends after DONE |
| `watch_task_not_found` | `WatchTaskStatus({bad_id})` | — | NOT_FOUND |

### 3.7 Authentication Integration

| Test | RPC | Expected |
|------|-----|----------|
| `unauthenticated_request_rejected` | `ListTargets` (no metadata) | UNAUTHENTICATED |
| `valid_jwt_accepted` | `ListTargets` + valid JWT | OK |
| `expired_jwt_rejected` | `ListTargets` + expired JWT | UNAUTHENTICATED |
| `insufficient_role_rejected` | `DeleteTarget` + observer JWT | PERMISSION_DENIED |

### 3.8 Concurrent & Edge Cases

| Test | Scope |
|------|-------|
| `concurrent_rpcs` | 100 parallel `ListTargets` → all succeed |
| `deadline_propagation` | Client sets 100ms deadline → server respects it |
| `cancelled_stream_cleanup` | Client drops stream midway → server stops sending |
| `max_message_size_enforced` | Request > configured max → RESOURCE_EXHAUSTED |

## 4. Contract Tests (Protobuf Compatibility)

### Backward Compatibility Checks

Using `buf breaking` against the previous version:

```bash
# In CI
buf breaking proto --against .git#branch=main
```

### Rules Enforced

- No removed fields
- No changed field numbers
- No changed field types
- No removed RPCs
- No removed services
- Enum values not renumbered

## 5. E2E Tests (Docker Compose)

### Test Environment

```yaml
# tests/docker-compose.yml
services:
  gvmd:
    image: greenbone/gvmd:latest
    # ... (Greenbone Community stack)

  gvm-grpc-api:
    build: ../..
    environment:
      GMP_SOCKET_PATH: /run/gvmd/gvmd.sock
    depends_on:
      gvmd:
        condition: service_healthy
```

### E2E Test Suite

| Test | Scenario |
|------|----------|
| `e2e_full_scan_lifecycle` | Create target → create task → start → watch status → get report |
| `e2e_stream_large_report` | Run scan → stream all results → verify count matches summary |
| `e2e_concurrent_streams` | 10 parallel report streams → all complete |
| `e2e_grpcurl_smoke` | `grpcurl` against running server → valid responses |

## 6. Performance Tests

| Test | Metric | Target |
|------|--------|--------|
| `throughput_list_targets` | RPCs/sec for `ListTargets` | > 5000 rps |
| `latency_p99_get_target` | p99 latency for `GetTarget` | < 20ms |
| `streaming_throughput` | Results/sec for `StreamReportResults` | > 10,000 results/sec |
| `streaming_memory` | Peak memory during 100k result stream | < 100MB |
| `concurrent_streams` | 50 simultaneous streams | All complete, no OOM |
| `connection_pool_contention` | 100 concurrent RPCs with pool_size=10 | All succeed (queued) |

## 7. Test Data & Fixtures

```
tests/
├── fixtures/
│   ├── proto_requests/
│   │   ├── create_target.pb          # Binary protobuf test data
│   │   └── create_task.pb
│   ├── gmp_responses/
│   │   ├── get_targets.xml
│   │   ├── get_report_100_results.xml
│   │   ├── get_report_50k_results.xml  # For streaming perf tests
│   │   └── error_not_found.xml
│   └── certs/                         # Test TLS certificates
│       ├── server.pem
│       ├── server.key
│       ├── client.pem
│       ├── client.key
│       └── ca.pem
```

## 8. CI Integration

```bash
# Unit + Integration (CI, fast)
cargo test --workspace

# E2E (requires Docker)
cargo test --workspace --features e2e-tests

# Contract (requires buf)
buf breaking proto --against .git#branch=main
```

Coverage target: **80%** line coverage for service implementations and interceptors.
