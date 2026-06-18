// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

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
