// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

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

/// Internal failures must not echo implementation details into RFC 9457 bodies.
#[test]
fn internal_error_problem_hides_private_detail() {
    let private_detail = "database password leaked in stack trace";
    let error =
        RestError::from_gateway_error(GatewayError::Internal(private_detail.to_string()), "/ready");

    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    let json = serde_json::to_value(&error.problem).unwrap();
    assert_eq!(
        json["detail"],
        serde_json::json!("An internal server error occurred.")
    );
    assert_ne!(json["detail"], serde_json::json!(private_detail));
}

/// Backend transport failures can contain socket paths or backend diagnostics.
#[test]
fn backend_unavailable_problem_hides_private_detail() {
    let private_detail = "failed to connect to /run/gvmd/gvmd.sock as admin";
    let error = RestError::from_gateway_error(
        GatewayError::BackendUnavailable(private_detail.to_string()),
        "/api/v1/tasks",
    );

    assert_eq!(error.status, StatusCode::BAD_GATEWAY);
    let json = serde_json::to_value(&error.problem).unwrap();
    assert_eq!(
        json["detail"],
        serde_json::json!("The backend service is unavailable.")
    );
    assert_ne!(json["detail"], serde_json::json!(private_detail));
}

/// Client-actionable validation details stay public so callers can fix requests.
#[test]
fn invalid_input_problem_keeps_client_actionable_detail() {
    let public_detail = "field 'name' is required";
    let error = RestError::from_gateway_error(
        GatewayError::InvalidInput(public_detail.to_string()),
        "/api/v1/targets",
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    let json = serde_json::to_value(&error.problem).unwrap();
    assert_eq!(json["detail"], serde_json::json!(public_detail));
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
