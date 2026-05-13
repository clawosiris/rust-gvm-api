// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Application-level error types shared by ports and use cases.

/// Application-level errors surfaced by ports and use cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// Backend service is unavailable or unhealthy.
    BackendUnavailable(String),
    /// Resource or route was not found.
    NotFound(String),
    /// Request input was invalid.
    InvalidInput(String),
    /// Session or credentials were invalid.
    Unauthorized(String),
    /// Resource state conflict (e.g. starting an already-running task).
    Conflict(String),
    /// Backend did not respond within the timeout.
    GatewayTimeout(String),
}
