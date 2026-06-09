// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Error handling for the REST adapter.

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_domain::{GatewayError, GatewayErrorCode};
use serde::Serialize;

const PROBLEM_TYPE_BASE_URL: &str = "https://gvm-gateway.greenbone.net/errors";

/// RFC 9457 problem details payload.
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    pub r#type: String,
    /// Stable machine-readable error identity.
    pub code: String,
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
        let status = status_for_gateway_error(&error);
        Self::from_parts(
            error.code(),
            title_for_code(error.code()),
            status,
            Some(error.detail().to_string()),
            Some(instance.into()),
        )
    }

    /// Builds a problem-details 404 for an unknown route.
    pub fn not_found(instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::NotFound,
            title_for_code(GatewayErrorCode::NotFound),
            StatusCode::NOT_FOUND,
            Some("The requested route does not exist.".to_string()),
            Some(instance.into()),
        )
    }

    /// Builds a 405 problem details response.
    pub fn method_not_allowed(instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "method-not-allowed",
            "method_not_allowed",
            "Method Not Allowed",
            StatusCode::METHOD_NOT_ALLOWED,
            Some("The requested HTTP method is not allowed for this route.".to_string()),
            Some(instance.into()),
        )
    }

    /// Builds a 403 problem details response.
    pub fn forbidden(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::Forbidden,
            title_for_code(GatewayErrorCode::Forbidden),
            StatusCode::FORBIDDEN,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 429 problem details response.
    pub fn too_many_requests(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_parts(
            GatewayErrorCode::TooManyRequests,
            title_for_code(GatewayErrorCode::TooManyRequests),
            StatusCode::TOO_MANY_REQUESTS,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    /// Builds a 503 problem details response.
    pub fn service_unavailable(detail: impl Into<String>, instance: impl Into<String>) -> Self {
        Self::from_custom_parts(
            "service-unavailable",
            "service_unavailable",
            "Service Unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
            Some(detail.into()),
            Some(instance.into()),
        )
    }

    fn from_parts(
        code: GatewayErrorCode,
        title: &'static str,
        status: StatusCode,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self::from_custom_parts(
            code.problem_slug(),
            code.as_str(),
            title,
            status,
            detail,
            instance,
        )
    }

    fn from_custom_parts(
        slug: &str,
        code: &str,
        title: &'static str,
        status: StatusCode,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            status,
            problem: ProblemDetails {
                r#type: format!("{PROBLEM_TYPE_BASE_URL}/{slug}"),
                code: code.to_string(),
                title: title.to_string(),
                status: status.as_u16(),
                detail,
                instance,
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

fn status_for_gateway_error(error: &GatewayError) -> StatusCode {
    match error {
        GatewayError::BackendUnavailable(_) => StatusCode::BAD_GATEWAY,
        GatewayError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        GatewayError::NotFound(_) => StatusCode::NOT_FOUND,
        GatewayError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        GatewayError::Unauthorized(_)
        | GatewayError::SessionExpired(_)
        | GatewayError::SessionInvalidated(_) => StatusCode::UNAUTHORIZED,
        GatewayError::Forbidden(_) => StatusCode::FORBIDDEN,
        GatewayError::Conflict(_) => StatusCode::CONFLICT,
        GatewayError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
        GatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        GatewayError::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
    }
}

fn title_for_code(code: GatewayErrorCode) -> &'static str {
    match code {
        GatewayErrorCode::BackendUnavailable => "Bad Gateway",
        GatewayErrorCode::NotImplemented => "Not Implemented",
        GatewayErrorCode::NotFound => "Not Found",
        GatewayErrorCode::BadRequest => "Bad Request",
        GatewayErrorCode::Unauthorized => "Unauthorized",
        GatewayErrorCode::SessionExpired => "Session Expired",
        GatewayErrorCode::SessionInvalidated => "Session Invalidated",
        GatewayErrorCode::Forbidden => "Forbidden",
        GatewayErrorCode::Conflict => "Conflict",
        GatewayErrorCode::TooManyRequests => "Too Many Requests",
        GatewayErrorCode::InternalServerError => "Internal Server Error",
        GatewayErrorCode::GatewayTimeout => "Gateway Timeout",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expired_problem_uses_https_type_and_public_code() {
        let error = RestError::from_gateway_error(
            GatewayError::SessionExpired("session expired".to_string()),
            "/api/v1/targets",
        );

        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        let json = serde_json::to_value(&error.problem).unwrap();
        assert_eq!(
            json["type"],
            serde_json::json!("https://gvm-gateway.greenbone.net/errors/session-expired")
        );
        assert_eq!(json["code"], serde_json::json!("session_expired"));
        assert_eq!(json["title"], serde_json::json!("Session Expired"));
    }

    #[test]
    fn route_not_found_problem_uses_public_code() {
        let error = RestError::not_found("/does-not-exist");

        assert_eq!(error.status, StatusCode::NOT_FOUND);
        let json = serde_json::to_value(&error.problem).unwrap();
        assert_eq!(json["code"], serde_json::json!("not_found"));
        assert_eq!(
            json["type"],
            serde_json::json!("https://gvm-gateway.greenbone.net/errors/not-found")
        );
    }

    #[test]
    fn service_unavailable_problem_uses_public_code() {
        let error = RestError::service_unavailable("draining", "/api/v1/targets");

        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        let json = serde_json::to_value(&error.problem).unwrap();
        assert_eq!(json["code"], serde_json::json!("service_unavailable"));
        assert_eq!(
            json["type"],
            serde_json::json!("https://gvm-gateway.greenbone.net/errors/service-unavailable")
        );
    }

    #[test]
    fn not_implemented_problem_uses_public_code() {
        let error = RestError::from_gateway_error(
            GatewayError::NotImplemented("backend does not support this command".to_string()),
            "/api/v1/reports/123/vulnerabilities",
        );

        assert_eq!(error.status, StatusCode::NOT_IMPLEMENTED);
        let json = serde_json::to_value(&error.problem).unwrap();
        assert_eq!(json["code"], serde_json::json!("not_implemented"));
        assert_eq!(json["title"], serde_json::json!("Not Implemented"));
        assert_eq!(
            json["type"],
            serde_json::json!("https://gvm-gateway.greenbone.net/errors/not-implemented")
        );
    }
}
