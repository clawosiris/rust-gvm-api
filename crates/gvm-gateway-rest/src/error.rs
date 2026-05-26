// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Error handling for the REST adapter.

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_domain::GatewayError;
use serde::Serialize;

/// RFC 9457 problem details payload.
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    pub r#type: String,
    /// Human-readable summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Occurrence-specific detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Request-specific instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// REST adapter error mapped to RFC 9457 problem details.
pub struct RestError {
    status: StatusCode,
    problem: ProblemDetails,
}

impl RestError {
    /// Builds a REST error from a domain error.
    pub fn from_gateway_error(error: GatewayError, instance: impl Into<String>) -> Self {
        let instance = Some(instance.into());

        match error {
            GatewayError::BackendUnavailable(detail) => Self {
                status: StatusCode::BAD_GATEWAY,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:bad-gateway".to_string(),
                    title: "Bad Gateway".to_string(),
                    status: StatusCode::BAD_GATEWAY.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
            GatewayError::NotFound(detail) => Self {
                status: StatusCode::NOT_FOUND,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:not-found".to_string(),
                    title: "Not Found".to_string(),
                    status: StatusCode::NOT_FOUND.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
            GatewayError::InvalidInput(detail) => Self {
                status: StatusCode::BAD_REQUEST,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:bad-request".to_string(),
                    title: "Bad Request".to_string(),
                    status: StatusCode::BAD_REQUEST.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
            GatewayError::Unauthorized(detail) => Self {
                status: StatusCode::UNAUTHORIZED,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:unauthorized".to_string(),
                    title: "Unauthorized".to_string(),
                    status: StatusCode::UNAUTHORIZED.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
            GatewayError::Conflict(detail) => Self {
                status: StatusCode::CONFLICT,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:conflict".to_string(),
                    title: "Conflict".to_string(),
                    status: StatusCode::CONFLICT.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
            GatewayError::GatewayTimeout(detail) => Self {
                status: StatusCode::GATEWAY_TIMEOUT,
                problem: ProblemDetails {
                    r#type: "urn:gvm-gateway:problem:gateway-timeout".to_string(),
                    title: "Gateway Timeout".to_string(),
                    status: StatusCode::GATEWAY_TIMEOUT.as_u16(),
                    detail: Some(detail),
                    instance,
                },
            },
        }
    }

    /// Builds a problem-details 404 for an unknown route.
    pub fn not_found(instance: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            problem: ProblemDetails {
                r#type: "urn:gvm-gateway:problem:not-found".to_string(),
                title: "Not Found".to_string(),
                status: StatusCode::NOT_FOUND.as_u16(),
                detail: Some("The requested route does not exist.".to_string()),
                instance: Some(instance.into()),
            },
        }
    }

    /// Builds a 405 problem details response.
    pub fn method_not_allowed(instance: impl Into<String>) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            problem: ProblemDetails {
                r#type: "urn:gvm-gateway:problem:method-not-allowed".to_string(),
                title: "Method Not Allowed".to_string(),
                status: StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                detail: Some(
                    "The requested HTTP method is not allowed for this route.".to_string(),
                ),
                instance: Some(instance.into()),
            },
        }
    }

    /// Builds a 403 problem details response.
    pub fn forbidden(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            problem: ProblemDetails {
                r#type: "urn:gvm-gateway:problem:forbidden".to_string(),
                title: "Forbidden".to_string(),
                status: StatusCode::FORBIDDEN.as_u16(),
                detail: Some(detail.into()),
                instance: Some(instance.into()),
            },
        }
    }

    /// Builds a 429 problem details response.
    pub fn too_many_requests(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            problem: ProblemDetails {
                r#type: "urn:gvm-gateway:problem:too-many-requests".to_string(),
                title: "Too Many Requests".to_string(),
                status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                detail: Some(detail.into()),
                instance: Some(instance.into()),
            },
        }
    }
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(self.problem),
        )
            .into_response()
    }
}
