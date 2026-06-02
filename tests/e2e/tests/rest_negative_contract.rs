// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, SessionResponse};
use reqwest::{
    header::{CONTENT_TYPE, LOCATION},
    Method, Response, StatusCode,
};

const MISSING_UUID: &str = "00000000-0000-0000-0000-000000000000";

// Covers live-stack negative REST contracts so malformed requests, unknown
// resources, and unsupported methods keep returning RFC 9457 problem responses.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_negative_contract_returns_problem_responses() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        let unknown_route = harness
            .request(Method::GET, "/api/v1/does-not-exist")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send unknown-route request")?;
        assert_problem_response(unknown_route, StatusCode::NOT_FOUND, "unknown route").await?;

        let method_not_allowed = harness
            .request(Method::PATCH, "/api/v1/targets")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send unsupported-method request")?;
        assert_problem_response(
            method_not_allowed,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported method",
        )
        .await?;

        let invalid_uuid = harness
            .request(Method::GET, "/api/v1/targets/not-a-uuid")
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send invalid UUID request")?;
        assert_problem_response(invalid_uuid, StatusCode::BAD_REQUEST, "invalid UUID").await?;

        let malformed_json = harness
            .request(Method::POST, "/api/v1/targets")
            .bearer_auth(&session.token)
            .header(CONTENT_TYPE, "application/json")
            .body("{")
            .send()
            .await
            .context("send malformed JSON request")?;
        assert_problem_response(malformed_json, StatusCode::BAD_REQUEST, "malformed JSON").await?;

        let missing_target = harness
            .request(Method::GET, &format!("/api/v1/targets/{MISSING_UUID}"))
            .bearer_auth(&session.token)
            .send()
            .await
            .context("send missing-target request")?;
        assert_problem_response(missing_target, StatusCode::NOT_FOUND, "missing target").await?;

        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    let session = harness.create_session().await?;
    Ok((harness, session))
}

async fn finish_session(
    harness: &E2eHarness,
    session: &SessionResponse,
    run: Result<()>,
) -> Result<()> {
    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }
    run
}

async fn assert_problem_response(
    response: Response,
    expected: StatusCode,
    action: &str,
) -> Result<()> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .with_context(|| format!("{action}: read response body"))?;

    assert_eq!(
        status, expected,
        "{action}: expected HTTP {expected} but received {status} with body {body}"
    );
    assert!(
        headers.get(LOCATION).is_none(),
        "{action}: problem response unexpectedly included Location"
    );
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/problem+json"),
        "{action}: expected application/problem+json but received {content_type}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("{action}: parse problem JSON"))?;
    assert_eq!(json["status"], serde_json::json!(expected.as_u16()));
    assert!(
        json["type"]
            .as_str()
            .is_some_and(|value| value.starts_with("https://gvm-gateway.greenbone.net/errors/")),
        "{action}: problem response did not include the gateway problem type"
    );
    for field in ["code", "title", "detail"] {
        assert!(
            json[field].as_str().is_some_and(|value| !value.is_empty()),
            "{action}: problem response field {field} was missing or empty"
        );
    }
    Ok(())
}
