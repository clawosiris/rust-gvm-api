# Proxy Access Control Analysis

## 1. Scope

This document describes how `rust-gvm-api` should enforce access control when one gateway fronts one or more `gvmd` endpoints.

It extends the basic gateway model with:

- client authentication
- endpoint authorization
- operation-level policy
- auditability across REST and gRPC

## 2. Core Design

The gateway is not only a protocol translator. It is also the access-control plane in front of the scanner estate.

```text
Client Identity
    │
    ▼
┌──────────────┐
│ Auth Layer   │  API keys / OIDC / mTLS / service identity
└──────┬───────┘
       ▼
┌──────────────┐
│ Policy Engine│  endpoint binding + operation permissions + limits
└──────┬───────┘
       ▼
┌──────────────┐
│ Gateway Core │  canonical operation catalog + audit + routing
└──────┬───────┘
       ▼
┌──────────────┐
│ rust-gvm     │  authenticated gvmd sessions / endpoint pools
└──────────────┘
```

## 3. Entity Model

The gateway needs three first-class entities:

### Client identity

- id
- auth method
- roles
- team or tenant metadata

### Managed endpoint

- endpoint id
- transport configuration
- credential reference
- connection-pool settings
- tags such as `production`, `staging`, `customer-a`

### Policy rule

- subject selector
- endpoint selector
- allowed operations
- denied operations
- optional schedule/limit constraints

## 4. Authorization Model

Start with RBAC, not ABAC.

Example operation categories:

| Category | Meaning |
| --- | --- |
| `read` | view tasks, targets, reports, version, configs |
| `scan` | create/start/stop scan workflows |
| `manage` | create/modify/delete managed resources |
| `admin` | user/settings/auth administration |
| `report` | read potentially sensitive report/result payloads |

Example role mapping:

| Role | Endpoint scope | Allowed categories |
| --- | --- | --- |
| `soc-analyst` | production scanners | `read`, `scan`, `report` |
| `devsecops` | staging scanners | `*` |
| `auditor` | all assigned scanners | `read`, `report` |
| `tenant-admin` | tenant-scoped scanners only | `*` within tenant |

Fine-grained command or operation-id permissions can sit beneath these categories when needed.

## 5. Request Flow

1. client authenticates to the gateway
2. gateway resolves identity and roles
3. client invokes a canonical operation through REST or gRPC
4. policy engine evaluates endpoint access, operation permission, and any limits
5. gateway routes the operation to the correct authenticated backend session
6. audit event records actor, endpoint, operation, surface, and result

The surface-specific adapter should be thin. Authorization belongs below the adapter boundary.

## 6. Multi-Surface Parity Rule

Every shipped public surface must respect the same policy semantics.

Examples:

| Canonical operation | REST surface | gRPC surface | Policy category |
| --- | --- | --- | --- |
| `targets.list` | `GET /api/v1/targets` | `ListTargets` | `read` |
| `tasks.start` | `POST /api/v1/tasks/{id}/start` | `StartTask` | `scan` |
| `reports.get` | `GET /api/v1/reports/{id}` | `GetReport` | `report` |

If a role may start tasks through REST, it should not be silently denied through gRPC for the same canonical operation.

## 7. Audit Requirements

Every operation should emit an audit event that includes:

- actor identity
- target endpoint
- canonical operation id
- public surface: `rest` or `grpc`
- allow/deny outcome
- backend result status

Agent activity arriving through the standalone [openvas-mcp-server](https://github.com/clawosiris/openvas-mcp-server) reaches the gateway as regular REST client traffic and is audited as such.

## 8. Delivery Phases

### Phase 1

- single-endpoint gateway
- REST adapter
- API-key or equivalent simple auth
- operation-level RBAC
- audit logging

### Phase 2

- multiple managed endpoints
- endpoint registry and routing
- tenant or environment segmentation
- per-endpoint pools and health checks

### Phase 3

- OIDC/enterprise identity integration
- richer policy model if needed
- gRPC surface expansion
- conformance tests that verify policy parity across REST/gRPC

## 9. Summary

The access-control design keeps the system coherent:

- one identity model
- one authorization model
- one audit model
- two peer public surfaces

With that structure, `rust-gvm-api` can own gateway security semantics cleanly while `rust-gvm` remains focused on backend execution.
