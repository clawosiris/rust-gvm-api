# What This Service Is For

`rust-gvm-api` is a REST gateway for Greenbone Vulnerability Management.

It is meant for two practical audiences:

- administrators who install and configure the gateway so it can talk to gvmd
- users or client developers who call the REST API to work with sessions,
  targets, tasks, reports, and related resources

For operators, the gateway provides a packaged service with explicit runtime
configuration. For API users, it provides a versioned HTTP/JSON interface and a
matching OpenAPI specification for the release they are using.

The current public surface of the released gateway is REST. The documentation
package shipped with the release is therefore focused on:

- installation and configuration
- authentication and connection patterns
- realistic API workflows
- the formal OpenAPI contract for this release
