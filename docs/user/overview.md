# Service Overview

## What `rust-gvm-api` is

`rust-gvm-api` is a gateway service for Greenbone Vulnerability Management
(GVM). It gives operators and client applications an HTTP/JSON interface over
gvmd while keeping GMP XML handling inside `rust-gvm`.

Instead of speaking raw GMP over a Unix socket or SSH connection, clients talk
to the gateway through a versioned REST API. The gateway owns session handling,
request validation, pagination, error mapping, and deployment-focused runtime
features such as tracing, transport-security modes, and packaged distribution
artifacts.

## What problem it solves

The service exists to make GVM integrations easier to build and operate:

- operators get a packaged gateway runtime with explicit configuration and
  release artifacts
- integrators get a stable HTTP/JSON contract instead of raw GMP XML
- API clients get predictable status codes, pagination, error shapes, and a
  published OpenAPI contract

## Role in the Greenbone / `rust-gvm` ecosystem

`rust-gvm-api` sits above `rust-gvm` and gvmd:

```text
Client -> rust-gvm-api -> rust-gvm -> gvmd
```

- `gvmd` remains the authoritative backend for scan and asset management
- `rust-gvm` owns GMP protocol typing and XML parsing
- `rust-gvm-api` exposes higher-level gateway behavior and deployment surfaces

The current shipped public surface is REST. gRPC and MCP remain planned but are
not part of the current runtime contract.

## Main capabilities

The gateway currently exposes:

- session-backed authentication and inspection
- core scan resources such as targets, tasks, reports, results, alerts, and
  schedules
- supporting resources such as scanners, scan configs, feeds, port lists,
  report formats, and credential stores
- asynchronous report export jobs
- operational endpoints such as `/health`, `/ready`, `/api/v1/version`, and
  `/api/v1/openapi.json`

## Intended audience

This package is written for three kinds of users:

- operators deploying the gateway in packages or containers
- integrators building internal services or automation on top of the REST API
- application developers writing direct API clients

## Supported interaction model

The release-aligned public contract is:

- REST over HTTP/JSON at `/api/v1`
- bearer-token session authentication after an initial Basic-auth session create
- published OpenAPI and narrative REST spec documents shipped with the release

Clients should treat the REST API and the included API spec as the supported
integration surface. Internal crate structure and maintainer-facing design notes
are not the primary client contract.
