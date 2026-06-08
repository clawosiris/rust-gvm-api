// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session lifecycle handlers for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{format_rfc3339, GatewayError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    dto::datetime_schema,
    error::RestError,
    openapi::{ok_json, problem_response},
    router::bearer_token,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// JSON body returned by `POST /api/v1/session`.
#[derive(Serialize, JsonSchema)]
#[schemars(rename = "SessionCreated")]
pub(crate) struct SessionCreatedResponse {
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: u64,
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

/// Session lifecycle state.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) enum SessionState {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "expired")]
    Expired,
}

fn parse_session_state(s: &str) -> SessionState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(SessionState::Active)
}

/// JSON body returned by `GET /api/v1/session`.
#[derive(Serialize, JsonSchema)]
#[schemars(rename = "SessionInfo")]
pub(crate) struct SessionInfoResponse {
    user: String,
    state: SessionState,
    #[serde(rename = "createdAt")]
    #[schemars(schema_with = "datetime_schema")]
    created_at: String,
    #[serde(rename = "lastUsedAt")]
    #[schemars(schema_with = "datetime_schema")]
    last_used_at: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a new session via HTTP Basic authentication.
///
/// `POST /api/v1/session`
pub async fn create_session(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let (username, password) = match extract_basic_credentials(&headers) {
        Ok(creds) => creds,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.create_session(&username, &password).await {
        Ok(created) => {
            let location = instance.clone();
            (
                StatusCode::CREATED,
                [(header::LOCATION, location)],
                Json(SessionCreatedResponse {
                    session_token: created.token,
                    expires_in: created.expires_in,
                    gmp_version: created.gmp_version,
                }),
            )
                .into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Inspect a session.
///
/// `GET /api/v1/session`
pub async fn get_session(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let token = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_session(&token) {
        Ok(info) => (
            StatusCode::OK,
            Json(SessionInfoResponse {
                user: info.user,
                state: parse_session_state(&info.state),
                created_at: format_rfc3339(info.created_at),
                last_used_at: format_rfc3339(info.last_used_at),
                expires_in: info.expires_in,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Close and destroy a session.
///
/// `DELETE /api/v1/session`
pub async fn delete_session(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let token = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.delete_session(&token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// Basic Auth
// ============================================================================

/// Extract `(username, password)` from an HTTP Basic `Authorization` header.
fn extract_basic_credentials(headers: &HeaderMap) -> Result<(String, String), GatewayError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| GatewayError::Unauthorized("missing Authorization header".to_string()))?;

    let encoded = value
        .strip_prefix("Basic ")
        .ok_or_else(|| GatewayError::Unauthorized("expected Basic authentication".to_string()))?;

    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| GatewayError::Unauthorized("invalid Base64 in credentials".to_string()))?;

    let decoded_str = String::from_utf8(decoded)
        .map_err(|_| GatewayError::Unauthorized("invalid UTF-8 in credentials".to_string()))?;

    let (username, password) = decoded_str
        .split_once(':')
        .ok_or_else(|| GatewayError::Unauthorized("malformed Basic credentials".to_string()))?;

    if username.is_empty() {
        return Err(GatewayError::Unauthorized(
            "username must not be empty".to_string(),
        ));
    }

    Ok((username.to_string(), password.to_string()))
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `POST /api/v1/session`.
pub(crate) fn create_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createSession")
        .tag("Sessions")
        .summary("Create a new session")
        .description(
            "Authenticates with the supplied Basic credentials and returns an opaque \
             session token. Include the token as a Bearer token on all subsequent requests.",
        )
        .security_requirement("basicAuth")
        .response_with::<201, Json<SessionCreatedResponse>, _>(ok_json("Session created"));

    let op = problem_response::<401>(op, "Authentication failed");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/session`.
pub(crate) fn get_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getSession")
        .tag("Sessions")
        .summary("Inspect a session")
        .description("Returns the current state and metadata for a session.")
        .security_requirement("bearerAuth")
        .response_with::<200, Json<SessionInfoResponse>, _>(ok_json("Session details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Session not found")
}

/// OpenAPI transform for `DELETE /api/v1/session`.
pub(crate) fn delete_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteSession")
        .tag("Sessions")
        .summary("Close and destroy a session")
        .description("Ends the session and invalidates the token immediately.")
        .security_requirement("bearerAuth")
        .response_with::<204, (), _>(|response| response.description("Session closed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Session not found")
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    // -- Basic auth extraction -----------------------------------------------

    /// Valid Basic auth header is decoded correctly.
    #[test]
    fn extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        // "admin:secret" → base64
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWRtaW46c2VjcmV0"),
        );
        let (user, pass) = extract_basic_credentials(&headers).unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    /// Missing Authorization header produces Unauthorized.
    #[test]
    fn extract_basic_credentials_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_basic_credentials(&headers);
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// Bearer prefix is rejected (must be Basic).
    #[test]
    fn extract_basic_credentials_bearer_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        let result = extract_basic_credentials(&headers);
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// Invalid base64 in the credentials is rejected.
    #[test]
    fn extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid!!!"),
        );
        let result = extract_basic_credentials(&headers);
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// Empty username is rejected.
    #[test]
    fn extract_basic_credentials_empty_username() {
        let mut headers = HeaderMap::new();
        // ":password" → base64
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic OnBhc3N3b3Jk"),
        );
        let result = extract_basic_credentials(&headers);
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// Password containing colons is preserved.
    #[test]
    fn extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        // "user:pass:word" → base64
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNzOndvcmQ="),
        );
        let (user, pass) = extract_basic_credentials(&headers).unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass:word");
    }
}
