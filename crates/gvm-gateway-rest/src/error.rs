// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Error handling for the REST adapter.

use axum::{
    http::StatusCode,
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
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        (self.status, Json(self.problem)).into_response()
    }
}
