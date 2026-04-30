# OpenSpec: GVM REST API (`gvm-rest-api`)

## 1. Overview

A RESTful API server that exposes Greenbone Vulnerability Management (GVM) operations over HTTP/JSON. Built on [axum](https://github.com/tokio-rs/axum) and [rust-gvm](https://github.com/clawosiris/rust-gvm), providing a standards-compliant alternative to GMP's raw XML protocol.

### Goals

- **Standards-first**: OpenAPI 3.1 specification, JSON:API-inspired resource design, proper HTTP semantics
- **Security-first**: Session-token authentication, TLS, rate limiting, audit logging
- **Observable**: Structured logging and OpenTelemetry (OTel) traces via OTLP
- **Performant**: Async throughout, connection pooling to gvmd, streaming for large responses

### Non-Goals

- Full GMP protocol parity in v0.1 (start with the most-used operations)
- Built-in user management (delegates to gvmd's user/role system via GMP)
- Web UI (API only — UIs are separate consumers)

### rust-gvm typed response policy

For GMP-backed endpoints, adapter/application conversion must use the structured response models provided by `rust-gvm`.

**Hard requirement:** `rust-gvm-api` must not parse or process raw GMP XML responses directly.
All GMP XML processing and protocol-shape handling belong in `rust-gvm`.

Current mandatory coverage (from `rust-gvm` PR #68):
- tasks (`GetTasksResponse`, `CreateTaskResponse`, `StartTaskResponse` + action aliases)
- reports (`GetReportsResponse`, `DeleteReportResponse`)
- results (`GetResultsResponse`)

When a structured model exists upstream, use it as the source for API mapping.


## 2. Architecture

```
┌─────────────────────────────────────────────────┐
│                  gvm-rest-api                    │
│                                                  │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  Router   │  │   Auth    │  │  Middleware   │ │
│  │  (axum)   │──│  (JWT /   │──│  (CORS/Rate/ │ │
│  │           │  │  API Key) │  │   Trace/Comp)│ │
│  └─────┬─────┘  └───────────┘  └──────────────┘ │
│        │                                         │
│  ┌─────┴─────────────────────────────────────┐   │
│  │           Service Layer                    │   │
│  │  ┌─────────┐ ┌──────────┐ ┌────────────┐ │   │
│  │  │ Scans   │ │ Targets  │ │  Reports    │ │   │
│  │  │ Service │ │ Service  │ │  Service    │ │   │
│  │  └────┬────┘ └────┬─────┘ └─────┬──────┘ │   │
│  └───────┼───────────┼─────────────┼────────┘   │
│          └───────────┼─────────────┘             │
│                ┌─────┴─────┐                     │
│                │ GMP Pool  │                     │
│                │(gvm-client│                     │
│                │ conn pool)│                     │
│                └─────┬─────┘                     │
└──────────────────────┼───────────────────────────┘
                       │ GMP/XML
                 ┌─────┴─────┐
                 │   gvmd    │
                 └───────────┘
```

### Crate Structure

```
crates/gvm-rest-api/
├── src/
│   ├── main.rs          # Entry point, server bootstrap
│   ├── lib.rs           # Library root
│   ├── config.rs        # CLI args + config file loading
│   ├── error.rs         # Error types → HTTP status mapping
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs       # JWT token validation
│   │   ├── api_key.rs   # API key authentication
│   │   └── rbac.rs      # Role-based access control
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── rate_limit.rs
│   │   ├── audit.rs     # Request/response audit logging
│   │   └── request_id.rs
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── health.rs    # GET /healthz, GET /readyz
│   │   ├── version.rs   # GET /api/v1/version
│   │   ├── scans.rs     # /api/v1/scans/*
│   │   ├── targets.rs   # /api/v1/targets/*
│   │   ├── tasks.rs     # /api/v1/tasks/*
│   │   ├── reports.rs   # /api/v1/reports/*
│   │   ├── results.rs   # /api/v1/results/*
│   │   ├── configs.rs   # /api/v1/scan-configs/*
│   │   ├── scanners.rs  # /api/v1/scanners/*
│   │   ├── alerts.rs    # /api/v1/alerts/*
│   │   ├── schedules.rs # /api/v1/schedules/*
│   │   ├── users.rs     # /api/v1/users/*
│   │   └── feeds.rs     # /api/v1/feeds/*
│   ├── models/
│   │   ├── mod.rs
│   │   ├── scan.rs
│   │   ├── target.rs
│   │   ├── task.rs
│   │   ├── report.rs
│   │   ├── result.rs
│   │   ├── pagination.rs
│   │   └── filter.rs
│   ├── pool.rs          # GMP connection pool
│   └── openapi.rs       # OpenAPI spec generation
├── tests/
│   ├── api/             # Integration tests per route
│   └── fixtures/        # Test data
└── Cargo.toml
```

## 3. API Design

### Base URL

```
/api/v1
```

### Versioning Strategy

URL-based versioning (`/api/v1/`, `/api/v2/`). Major breaking changes increment version. Minor additions are non-breaking.

### Resource Endpoints

#### Targets

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/targets` | List targets (paginated, filterable) |
| `POST` | `/api/v1/targets` | Create a target |
| `GET` | `/api/v1/targets/{id}` | Get target by ID |
| `PUT` | `/api/v1/targets/{id}` | Update target |
| `DELETE` | `/api/v1/targets/{id}` | Delete target |

#### Tasks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/tasks` | List tasks |
| `POST` | `/api/v1/tasks` | Create task |
| `GET` | `/api/v1/tasks/{id}` | Get task |
| `PUT` | `/api/v1/tasks/{id}` | Update task |
| `DELETE` | `/api/v1/tasks/{id}` | Delete task |
| `POST` | `/api/v1/tasks/{id}/start` | Start task |
| `POST` | `/api/v1/tasks/{id}/stop` | Stop task |
| `POST` | `/api/v1/tasks/{id}/resume` | Resume task |

#### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/reports` | List reports |
| `GET` | `/api/v1/reports/{id}` | Get report (with results) |
| `GET` | `/api/v1/reports/{id}/results` | Get report results (paginated) |
| `DELETE` | `/api/v1/reports/{id}` | Delete report |
| `GET` | `/api/v1/reports/{id}/export` | Export report (PDF/XML/CSV) |

#### Results

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/results` | List results (paginated, filterable) |
| `GET` | `/api/v1/results/{id}` | Get individual result |

#### Scan Configs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scan-configs` | List scan configurations |
| `POST` | `/api/v1/scan-configs` | Create scan config |
| `GET` | `/api/v1/scan-configs/{id}` | Get scan config |
| `PUT` | `/api/v1/scan-configs/{id}` | Update scan config |
| `DELETE` | `/api/v1/scan-configs/{id}` | Delete scan config |

#### Scanners

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scanners` | List scanners |
| `GET` | `/api/v1/scanners/{id}` | Get scanner |

#### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/alerts` | List alerts |
| `POST` | `/api/v1/alerts` | Create alert |
| `GET` | `/api/v1/alerts/{id}` | Get alert |
| `PUT` | `/api/v1/alerts/{id}` | Update alert |
| `DELETE` | `/api/v1/alerts/{id}` | Delete alert |

#### Schedules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/schedules` | List schedules |
| `POST` | `/api/v1/schedules` | Create schedule |
| `GET` | `/api/v1/schedules/{id}` | Get schedule |
| `PUT` | `/api/v1/schedules/{id}` | Update schedule |
| `DELETE` | `/api/v1/schedules/{id}` | Delete schedule |

#### Users & Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/token` | Authenticate, get JWT |
| `POST` | `/api/v1/auth/refresh` | Refresh JWT |
| `GET` | `/api/v1/users` | List users |
| `GET` | `/api/v1/users/me` | Get current user |

#### Feeds

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/feeds` | List feed status |
| `POST` | `/api/v1/feeds/sync` | Trigger feed sync |

#### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe (checks gvmd connectivity) |
| `GET` | `/api/v1/version` | API + GMP version info |
| `GET` | `/api/v1/openapi.json` | OpenAPI 3.1 spec |
| `GET` | `/api/v1/docs` | Swagger UI |
| `GET` | `/api/v1/redoc` | ReDoc documentation |

### Request/Response Conventions

#### Pagination

```http
GET /api/v1/targets?page=1&per_page=25&sort=name&order=asc
```

Response includes pagination metadata:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 25,
    "total": 142,
    "total_pages": 6
  }
}
```

#### Filtering

GMP filter strings exposed as query parameters:

```http
GET /api/v1/results?severity_min=7.0&host=192.168.1.0/24&task_id=<uuid>
```

#### Error Responses

RFC 7807 Problem Details:

```json
{
  "type": "https://api.gvm.example/errors/not-found",
  "title": "Resource Not Found",
  "status": 404,
  "detail": "Target with ID '550e8400-e29b-41d4-a716-446655440000' not found.",
  "instance": "/api/v1/targets/550e8400-e29b-41d4-a716-446655440000"
}
```

#### Distributed tracing

The API should propagate W3C Trace Context (`traceparent`, `tracestate`, optional `baggage`) for OpenTelemetry correlation.

### Authentication & Authorization

1. **Bearer token flow** — current delivered auth model
   - clients obtain an opaque bearer token out of band
   - subsequent requests use `Authorization: Bearer <token>`
   - the gateway keeps an internal session-backed execution model

2. **Public session endpoints**
   - REST session-management endpoints are deferred to a later phase

3. **Authorization**
   - Authorization behavior follows gvmd user permissions
   - API adapters map domain permission errors to protocol-specific status codes

### Rate Limiting

Token-bucket rate limiting per API key / JWT subject:
- Default: 100 req/s per client
- Configurable per-endpoint overrides
- `429 Too Many Requests` with `Retry-After` header

## 4. Configuration

```toml
# gvm-rest-api.toml

[server]
bind = "0.0.0.0:8080"
tls_cert = "/etc/gvm-api/tls/cert.pem"
tls_key = "/etc/gvm-api/tls/key.pem"
request_timeout_secs = 30
body_limit_bytes = 10_485_760  # 10 MB

[gmp]
transport = "unix"  # "unix" | "ssh" | "tls"
socket_path = "/run/gvmd/gvmd.sock"
# ssh_host = "gvmd.local"
# ssh_port = 22
# ssh_user = "gvm"
pool_size = 10
connect_timeout_secs = 5
request_timeout_secs = 60

[auth]
jwt_secret = "${JWT_SECRET}"  # env var expansion
jwt_expiration_secs = 3600
jwt_refresh_expiration_secs = 86400
api_key_enabled = true

[rate_limit]
default_rps = 100
burst = 150

[logging]
format = "json"  # "json" | "pretty"
level = "info"

[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "gvm-rest-api"
```

CLI flags override config file values; environment variables override both.

## 5. Implementation Phases (REST-first, aligned with #26 and #27)

This plan is aligned with:

- General architecture proposal: https://github.com/clawosiris/rust-gvm-api/issues/26
- Connection pooling + session handling proposal: https://github.com/clawosiris/rust-gvm-api/issues/27

Scope of this plan is **REST API only** (implementation of the proposed OpenAPI spec under `spec/rest-api/`).
**gRPC is explicitly deferred to a later iteration.**

### Delivery approach: acceptance-test first (mandatory)

For every use case and endpoint, development follows this loop:

1. Write or extend an **acceptance test** for the behavior.
2. Run the test and confirm it **fails** (red) for the expected reason.
3. Implement the minimal code to satisfy the behavior.
4. Re-run and confirm the acceptance test is **green**.
5. Refactor while keeping the acceptance test green.

No implementation work should start without an acceptance test that defines the expected behavior.

### Phase 1: Architecture skeleton (hexagonal baseline)

- Create crate boundaries per #26:
  - `gvm-gateway-domain` (session model, domain services, port traits)
  - `gvm-gateway-app` (use cases: session lifecycle + GMP execution)
  - `gvm-gateway-rest` (REST incoming adapter)
  - `gvm-gateway-gvmd` (outgoing adapter)
  - `gvm-gateway` (composition root)
- Keep domain free from framework/I/O dependencies.
- Wire REST adapter to application use cases only.
- Keep gRPC crate/work out of scope for this iteration.

### Phase 2: Session-backed execution core (from #27)

- Implement domain `SessionManager` with `create/get/touch/expire/remove`.
- Implement gvmd adapter connection store keyed by session token.
- Add one in-flight GMP command serialization per session where needed.
- Treat session lifecycle limits and cleanup as internal implementation behavior for now.

### Phase 3: REST adapter foundation (spec-first)

- Generate REST server stubs/types from the OpenAPI 3.1 spec in `spec/rest-api/`.
- Implement bearer-token extraction and protected route handling for Targets CRUD.
- Map domain errors to HTTP status/problem responses consistently.
- Defer public `/sessions` endpoints to a later phase.

### Phase 4: Resource endpoint implementation (proposed spec)

Implement REST resources against the shared application execution path (`execute(token, command)`):

- Targets
- Tasks (+ start/stop/resume) — use `rust-gvm` structured task responses
- Reports (+ report results) — use `rust-gvm` structured report responses
- Results — use `rust-gvm` structured result responses
- Scan configs
- Scanners
- Alerts
- Schedules
- Credentials
- Port lists
- Feeds
- Version/System

For each resource (acceptance-test first):
- preserve API contract from OpenAPI spec
- ensure token-scoped execution and per-session GMP serialization
- keep adapter thin (translation only, no business logic, no raw GMP XML handling)

### Phase 5: REST hardening and release readiness

- Add structured observability for REST flow (logs, OTel tracing).
- Implement OTel tracer setup with OTLP exporter and service/resource attributes.
- Ensure W3C Trace Context propagation across incoming HTTP, application use cases, and gvmd adapter calls.
- Add resilience checks for session expiry, backend disconnects, and queue backpressure.
- Add/maintain integration and E2E tests focused on REST behavior (written first, fail-first):
  - session lifecycle
  - concurrent calls on same token serialize correctly
  - limit enforcement and teardown behavior
- Prepare first REST-focused release cut.

### Deferred to next iteration

- gRPC adapter implementation and `.proto` contract integration.
- Cross-adapter parity tests (REST vs gRPC).

## 6. Error Handling

### GMP → HTTP Status Mapping

| GMP Condition | HTTP Status |
|---------------|-------------|
| Success | `200 OK` / `201 Created` |
| Resource not found | `404 Not Found` |
| Authentication failed | `401 Unauthorized` |
| Permission denied | `403 Forbidden` |
| Invalid request | `400 Bad Request` |
| Resource conflict | `409 Conflict` |
| GMP connection failure | `502 Bad Gateway` |
| GMP timeout | `504 Gateway Timeout` |
| Internal error | `500 Internal Server Error` |

## 7. Dependencies

### Runtime

| Dependency | Purpose |
|------------|---------|
| `gvm-client` / `gvm-gmp` | GMP protocol client + structured response models (tasks/reports/results from rust-gvm PR #68) |
| `axum` | HTTP framework |
| `tower` / `tower-http` | Middleware (CORS, compression, auth, trace context propagation) |
| `tokio` | Async runtime |
| `utoipa` | OpenAPI spec generation |
| `serde` / `serde_json` | Serialization |
| `jsonwebtoken` | JWT handling |
| `clap` | CLI argument parsing |
| `tracing` + `tracing-opentelemetry` + `opentelemetry` + `opentelemetry-otlp` | Structured logging + OTel export |
| `prometheus` | Metrics |

### Dev/Test

| Dependency | Purpose |
|------------|---------|
| `rstest` | Parameterized tests |
| `wiremock` | HTTP mock server (for downstream tests) |
| `assert_json_diff` | JSON response assertion |

## 8. Security Considerations

- **No credential storage**: JWT secret from env var, GMP credentials per-session
- **TLS everywhere**: Support native TLS for API + GMP transport
- **Input validation**: All request bodies validated before GMP translation
- **No unsafe code**: `#[deny(unsafe_code)]` crate-wide
- **CORS**: Configurable origin allowlist (deny by default)
- **Headers**: Security headers via tower-http (X-Content-Type-Options, X-Frame-Options, etc.)

## 9. Open Questions

- [ ] Should we support GMP filter syntax passthrough or only structured query params?
- [ ] WebSocket vs SSE for real-time task status updates?
- [ ] Connection pool strategy after public session endpoints land: per-user sessions or shared pool with per-request auth?
- [ ] Should report export be synchronous or async (poll-based)?
