// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use axum::{
    body::Body,
    http::{header, Request},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use super::uses_request_scoped_basic_auth;

fn basic_request(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", BASE64.encode("alice:secret")),
        )
        .body(Body::empty())
        .unwrap()
}

#[test]
fn request_scoped_basic_auth_skips_public_routes() {
    for path in [
        "/health",
        "/ready",
        "/api/v1/version",
        "/api/v1/openapi.json",
    ] {
        assert!(
            !uses_request_scoped_basic_auth(&basic_request("GET", path)),
            "{path} should stay public"
        );
    }
}

#[test]
fn request_scoped_basic_auth_keeps_session_lifecycle_special_cases() {
    assert!(!uses_request_scoped_basic_auth(&basic_request(
        "POST",
        "/api/v1/session"
    )));
    assert!(!uses_request_scoped_basic_auth(&basic_request(
        "GET",
        "/api/v1/session"
    )));
}

#[test]
fn request_scoped_basic_auth_applies_to_protected_routes_by_default() {
    for path in [
        "/api/v1/alerts",
        "/api/v1/credentials/stores",
        "/api/v1/feeds",
        "/api/v1/report-formats",
        "/api/v1/timezones",
        "/api/v1/users",
        "/api/v1/future-resource",
    ] {
        assert!(
            uses_request_scoped_basic_auth(&basic_request("GET", path)),
            "{path} should use request-scoped Basic auth"
        );
    }
}
