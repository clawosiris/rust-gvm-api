// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session lifecycle handlers for the REST adapter.

use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    format_rfc3339, AuthPort, GatewayError, ReportPort, ResultPort, SystemPort, TargetPort,
    TaskPort,
};
use serde::Serialize;

use crate::error::RestError;

// ============================================================================
// Response DTOs
// ============================================================================

/// JSON body returned by `POST /api/v1/sessions`.
#[derive(Serialize)]
struct SessionCreatedResponse {
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: u64,
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

/// JSON body returned by `GET /api/v1/sessions/{token}`.
#[derive(Serialize)]
struct SessionInfoResponse {
    #[serde(rename = "sessionToken")]
    session_token: String,
    user: String,
    state: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "lastUsedAt")]
    last_used_at: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a new session via HTTP Basic authentication.
///
/// `POST /api/v1/sessions`
pub async fn create_session<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: Send + Sync + 'static,
    Sn: Send + Sync + 'static,
{
    let instance = uri.path().to_string();
    let (username, password) = match extract_basic_credentials(&headers) {
        Ok(creds) => creds,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.create_session(&username, &password).await {
        Ok(created) => (
            StatusCode::CREATED,
            Json(SessionCreatedResponse {
                session_token: created.token,
                expires_in: created.expires_in,
                gmp_version: created.gmp_version,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Inspect a session.
///
/// `GET /api/v1/sessions/{token}`
pub async fn get_session<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
    Path(token): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: Send + Sync + 'static,
    Sn: Send + Sync + 'static,
{
    let instance = uri.path().to_string();

    match service.get_session(&token) {
        Ok(info) => (
            StatusCode::OK,
            Json(SessionInfoResponse {
                session_token: info.token,
                user: info.user,
                state: info.state,
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
/// `DELETE /api/v1/sessions/{token}`
pub async fn delete_session<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
    Path(token): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: Send + Sync + 'static,
    Sn: Send + Sync + 'static,
{
    let instance = uri.path().to_string();

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
