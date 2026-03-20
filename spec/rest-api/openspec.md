# OpenSpec: GVM REST API (`gvm-rest-api`)

## 1. Overview

A RESTful API server that exposes Greenbone Vulnerability Management (GVM) operations over HTTP/JSON. Built on [axum](https://github.com/tokio-rs/axum) and [rust-gvm](https://github.com/clawosiris/rust-gvm), providing a standards-compliant alternative to GMP's raw XML protocol.

### Goals

- **Standards-first**: OpenAPI 3.1 specification, JSON:API-inspired resource design, proper HTTP semantics
- **Security-first**: JWT/API-key authentication, RBAC, TLS, rate limiting, audit logging
- **Observable**: Structured logging, OpenTelemetry traces, Prometheus metrics
- **Performant**: Async throughout, connection pooling to gvmd, streaming for large responses

### Non-Goals

- Full GMP protocol parity in v0.1 (start with the most-used operations)
- Built-in user management (delegates to gvmd's user/role system via GMP)
- Web UI (API only — UIs are separate consumers)

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
| `GET` | `/metrics` | Prometheus metrics |
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

#### Request IDs

Every response includes `X-Request-Id` header for tracing.

### Authentication & Authorization

1. **JWT Bearer Tokens** — Primary auth for interactive clients
   - `POST /api/v1/auth/token` with GMP credentials → JWT
   - Token includes user roles from gvmd
   - Configurable expiration (default 1h) + refresh tokens

2. **API Keys** — For service-to-service / automation
   - Passed via `X-API-Key` header
   - Scoped to specific operations (read-only, full access)

3. **RBAC** — Maps GMP roles to API permissions
   - Admin, User, Observer, Guest mapped from gvmd roles
   - Per-endpoint permission checks

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

## 5. Implementation Phases

### Phase 1: Foundation (MVP)

- Server bootstrap (axum + tower)
- Health endpoints (`/healthz`, `/readyz`)
- GMP connection pool
- Version endpoint
- Basic error handling with RFC 7807
- Structured logging (tracing)
- Configuration system (clap + config)

### Phase 2: Core Resources

- Targets CRUD
- Tasks CRUD + start/stop/resume
- Reports list + get
- Results list + get
- Scan configs list + get
- Pagination + filtering
- OpenAPI spec generation (utoipa)
- Swagger UI + ReDoc

### Phase 3: Auth & Security

- JWT authentication
- API key authentication
- RBAC middleware
- Rate limiting
- CORS configuration
- TLS support
- Audit logging
- Request ID propagation

### Phase 4: Advanced Features

- Report export (PDF/XML/CSV)
- Alerts CRUD
- Schedules CRUD
- Scanners list
- Users/feeds endpoints
- Prometheus metrics
- OpenTelemetry integration
- WebSocket endpoint for task status streaming (optional)

### Phase 5: Production Readiness

- Container image (Dockerfile + docker-compose)
- Helm chart (optional)
- Graceful shutdown
- Connection draining
- Health check with gvmd connectivity
- Performance benchmarks

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
| `gvm-client` / `gvm-gmp` | GMP protocol client (from rust-gvm) |
| `axum` | HTTP framework |
| `tower` / `tower-http` | Middleware (CORS, compression, tracing, auth) |
| `tokio` | Async runtime |
| `utoipa` | OpenAPI spec generation |
| `serde` / `serde_json` | Serialization |
| `jsonwebtoken` | JWT handling |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
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
- [ ] Connection pool strategy: per-user sessions or shared pool with per-request auth?
- [ ] Should report export be synchronous or async (poll-based)?
