# Usage Guidance

## Getting the service

`rust-gvm-api` release outputs are published through GitHub releases. The
release pipeline currently produces:

- Debian packages
- Arch Linux packages
- an OCI image archive
- an SBOM archive
- this user documentation package

Choose the delivery format that matches your environment, then deploy the
gateway close to the gvmd instance it serves.

## Runtime model

The gateway is not a replacement for gvmd. It is a separate process that talks
to gvmd on the operator's behalf. A deployment therefore needs:

- a reachable gvmd instance
- a gateway configuration that points at the gvmd socket or endpoint
- user credentials that gvmd accepts

## Configuration expectations

Important configuration assumptions for current releases:

- packaged installs ship an example config at
  `/etc/gvm-gateway/gvm-gateway.toml.example`
- the canonical package config path is
  `/etc/gvm-gateway/gvm-gateway.toml`
- container deployments can use environment variables and the container-focused
  example config in `packaging/gvm-gateway.container.toml`
- the default gvmd backend endpoint is `unix:///run/gvmd/gvmd.sock`

Configuration is versioned with the gateway release. When behavior differs by
deployment mode, prefer the config examples and release-specific docs from the
same release package over older repository snippets.

## Authentication expectations

The REST workflow is session-based:

1. `POST /api/v1/session` with HTTP Basic credentials that gvmd accepts
2. receive an opaque `sessionToken`
3. send `Authorization: Bearer <sessionToken>` on subsequent API requests
4. close the session with `DELETE /api/v1/session` when finished

The returned `expiresIn` value is an idle timeout in seconds. Clients should not
assume sessions are permanent.

## Connecting to the API

Typical local base URLs are:

- package/service deployment behind a local reverse proxy:
  `http://127.0.0.1:8080/api/v1`
- container deployment with published port:
  `http://<host>:8080/api/v1`

Operational probes live outside `/api/v1`:

- `/health`
- `/ready`

The REST contract is also exposed at runtime:

- `GET /api/v1/openapi.json`

## Transport security and proxies

Current releases support three transport modes:

- `disabled`
- `terminated_by_proxy`
- `native`

For production-style deployments, `terminated_by_proxy` or `native` is usually
the right choice. When running behind a TLS-terminating proxy, configure trusted
proxy CIDRs explicitly rather than assuming forwarded headers are accepted from
any source.

## Version-specific behavior

Version alignment matters for:

- request and response shapes
- supported endpoints
- packaged configuration expectations
- release artifact names and checksums

When documenting or automating against the gateway, pin examples to the release
you actually deploy and keep the shipped OpenAPI tree nearby.
