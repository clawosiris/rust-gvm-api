// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Application-level error taxonomy shared by ports and use cases.

/// Stable machine-readable error identity shared across adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayErrorCode {
    /// Backend connection or dependency failure.
    BackendUnavailable,
    /// Requested operation is not implemented by the current backend.
    NotImplemented,
    /// Requested resource or route was not found.
    NotFound,
    /// Request input was invalid.
    BadRequest,
    /// Authentication failed.
    Unauthorized,
    /// Session expired due to idle timeout or cleanup.
    SessionExpired,
    /// Session token is missing or otherwise no longer valid.
    SessionInvalidated,
    /// Caller is authenticated but not permitted.
    Forbidden,
    /// Resource state conflict.
    Conflict,
    /// Rate limit exceeded.
    TooManyRequests,
    /// Unhandled internal failure.
    InternalServerError,
    /// Backend did not respond before the timeout.
    GatewayTimeout,
}

impl GatewayErrorCode {
    /// Returns the stable public `code` string for this error identity.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackendUnavailable => "backend_unavailable",
            Self::NotImplemented => "not_implemented",
            Self::NotFound => "not_found",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::SessionExpired => "session_expired",
            Self::SessionInvalidated => "session_invalidated",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::TooManyRequests => "too_many_requests",
            Self::InternalServerError => "internal_server_error",
            Self::GatewayTimeout => "gateway_timeout",
        }
    }

    /// Returns the canonical problem-type slug for this error identity.
    pub fn problem_slug(self) -> &'static str {
        match self {
            Self::BackendUnavailable => "bad-gateway",
            Self::NotImplemented => "not-implemented",
            Self::NotFound => "not-found",
            Self::BadRequest => "bad-request",
            Self::Unauthorized => "unauthorized",
            Self::SessionExpired => "session-expired",
            Self::SessionInvalidated => "session-invalidated",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::TooManyRequests => "too-many-requests",
            Self::InternalServerError => "internal-server-error",
            Self::GatewayTimeout => "gateway-timeout",
        }
    }
}

/// Application-level errors surfaced by ports and use cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// Backend service is unavailable or unhealthy.
    BackendUnavailable(String),
    /// Requested operation is not implemented by the current backend.
    NotImplemented(String),
    /// Resource or route was not found.
    NotFound(String),
    /// Request input was invalid.
    InvalidInput(String),
    /// Session or credentials were invalid.
    Unauthorized(String),
    /// Session expired due to timeout or cleanup.
    SessionExpired(String),
    /// Session token is missing or otherwise invalidated.
    SessionInvalidated(String),
    /// Caller lacks permission for the requested action.
    Forbidden(String),
    /// Resource state conflict (e.g. starting an already-running task).
    Conflict(String),
    /// Rate limit exceeded.
    TooManyRequests(String),
    /// Internal unhandled failure.
    Internal(String),
    /// Backend did not respond within the timeout.
    GatewayTimeout(String),
}

impl GatewayError {
    /// Returns the stable canonical identity for this error variant.
    pub fn code(&self) -> GatewayErrorCode {
        match self {
            Self::BackendUnavailable(_) => GatewayErrorCode::BackendUnavailable,
            Self::NotImplemented(_) => GatewayErrorCode::NotImplemented,
            Self::NotFound(_) => GatewayErrorCode::NotFound,
            Self::InvalidInput(_) => GatewayErrorCode::BadRequest,
            Self::Unauthorized(_) => GatewayErrorCode::Unauthorized,
            Self::SessionExpired(_) => GatewayErrorCode::SessionExpired,
            Self::SessionInvalidated(_) => GatewayErrorCode::SessionInvalidated,
            Self::Forbidden(_) => GatewayErrorCode::Forbidden,
            Self::Conflict(_) => GatewayErrorCode::Conflict,
            Self::TooManyRequests(_) => GatewayErrorCode::TooManyRequests,
            Self::Internal(_) => GatewayErrorCode::InternalServerError,
            Self::GatewayTimeout(_) => GatewayErrorCode::GatewayTimeout,
        }
    }

    /// Returns the canonical problem-type slug for this error variant.
    pub fn problem_slug(&self) -> &'static str {
        self.code().problem_slug()
    }

    /// Returns the occurrence-specific detail string.
    pub fn detail(&self) -> &str {
        match self {
            Self::BackendUnavailable(detail)
            | Self::NotImplemented(detail)
            | Self::NotFound(detail)
            | Self::InvalidInput(detail)
            | Self::Unauthorized(detail)
            | Self::SessionExpired(detail)
            | Self::SessionInvalidated(detail)
            | Self::Forbidden(detail)
            | Self::Conflict(detail)
            | Self::TooManyRequests(detail)
            | Self::Internal(detail)
            | Self::GatewayTimeout(detail) => detail,
        }
    }
}
