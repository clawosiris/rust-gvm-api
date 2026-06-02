// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, SessionResponse};
use reqwest::{
    header::{HeaderMap, CONTENT_TYPE},
    Method, Response, StatusCode,
};

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
const TRACESTATE: &str = "vendor=value";

// Covers live-stack response envelope guarantees that clients and operators
// depend on across both success and problem responses: media type, security
// headers, RFC 9457 problem fields, and W3C trace-context response headers
// without echoing baggage.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_cross_cutting_headers_are_present_on_success_and_problem_responses() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        let success = harness
            .request(Method::GET, "/api/v1/targets")
            .bearer_auth(&session.token)
            .header("traceparent", TRACEPARENT)
            .header("tracestate", TRACESTATE)
            .header("baggage", "user_id=123")
            .send()
            .await
            .context("send traced success request")?;
        assert_eq!(success.status(), StatusCode::OK);
        assert_json_content_type(success.headers(), "success response");
        assert_security_headers(success.headers(), "success response");
        assert_trace_headers(success.headers(), "success response");

        let problem = harness
            .request(Method::GET, "/api/v1/targets")
            .header("traceparent", TRACEPARENT)
            .header("tracestate", TRACESTATE)
            .header("baggage", "user_id=123")
            .send()
            .await
            .context("send traced problem request")?;
        assert_problem_response(problem, StatusCode::UNAUTHORIZED).await
    }
    .await;

    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }

    run
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
    Ok((harness, session))
}

async fn assert_problem_response(response: Response, expected: StatusCode) -> Result<()> {
    assert_eq!(response.status(), expected);
    assert_problem_content_type(response.headers(), "problem response");
    assert_security_headers(response.headers(), "problem response");
    assert_trace_headers(response.headers(), "problem response");

    let json = response
        .json::<serde_json::Value>()
        .await
        .context("parse problem response body")?;
    assert_eq!(json["status"], serde_json::json!(expected.as_u16()));
    assert!(
        json["type"]
            .as_str()
            .is_some_and(|value| value.starts_with("https://gvm-gateway.greenbone.net/errors/")),
        "problem response did not include the gateway problem type"
    );
    for field in ["code", "title", "detail"] {
        assert!(
            json[field].as_str().is_some_and(|value| !value.is_empty()),
            "problem response field {field} was missing or empty"
        );
    }
    Ok(())
}

fn assert_json_content_type(headers: &HeaderMap, context: &str) {
    let content_type = header_value(headers, CONTENT_TYPE, context);
    assert!(
        content_type.starts_with("application/json"),
        "{context} used unexpected Content-Type {content_type}"
    );
}

fn assert_problem_content_type(headers: &HeaderMap, context: &str) {
    let content_type = header_value(headers, CONTENT_TYPE, context);
    assert!(
        content_type.starts_with("application/problem+json"),
        "{context} used unexpected Content-Type {content_type}"
    );
}

fn assert_security_headers(headers: &HeaderMap, context: &str) {
    assert_eq!(
        header_value(headers, "x-content-type-options", context),
        "nosniff"
    );
    assert_eq!(header_value(headers, "x-frame-options", context), "DENY");
    assert_eq!(
        header_value(headers, "referrer-policy", context),
        "no-referrer"
    );
    assert_eq!(header_value(headers, "cache-control", context), "no-store");
}

fn assert_trace_headers(headers: &HeaderMap, context: &str) {
    assert_eq!(header_value(headers, "traceparent", context), TRACEPARENT);
    assert_eq!(header_value(headers, "tracestate", context), TRACESTATE);
    assert!(
        headers.get("baggage").is_none(),
        "{context} echoed request baggage"
    );
}

fn header_value<'a, K>(headers: &'a HeaderMap, key: K, context: &str) -> &'a str
where
    K: reqwest::header::AsHeaderName,
{
    headers
        .get(key)
        .unwrap_or_else(|| panic!("{context} was missing expected header"))
        .to_str()
        .unwrap_or_else(|error| panic!("{context} included a non-UTF8 header value: {error}"))
}
