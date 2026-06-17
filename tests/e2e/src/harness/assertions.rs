// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use reqwest::{header, StatusCode};

use super::{http::truncate, ProblemResponse};

pub async fn assert_problem_response(
    response: reqwest::Response,
    expected_status: StatusCode,
    action: &str,
) -> Result<ProblemResponse> {
    assert_problem_response_any(response, &[expected_status], action).await
}

pub async fn assert_problem_response_any(
    response: reqwest::Response,
    expected_statuses: &[StatusCode],
    action: &str,
) -> Result<ProblemResponse> {
    assert!(
        !expected_statuses.is_empty(),
        "{action}: expected at least one status"
    );

    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .with_context(|| format!("{action}: read problem response body"))?;

    assert!(
        expected_statuses.contains(&status),
        "{action}: expected one of {:?} but received {status} with body {body}",
        expected_statuses
    );
    assert!(
        headers.get(header::LOCATION).is_none(),
        "{action}: problem response unexpectedly included Location"
    );

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/problem+json"),
        "{action}: expected application/problem+json but received {content_type}"
    );

    let problem: ProblemResponse = serde_json::from_str(&body)
        .with_context(|| format!("{action}: parse problem JSON: {}", truncate(&body)))?;
    assert_eq!(
        problem.status,
        status.as_u16(),
        "{action}: problem body status did not match HTTP status"
    );
    assert!(
        problem
            .problem_type
            .starts_with("https://gvm-gateway.greenbone.net/errors/"),
        "{action}: problem response did not include the gateway problem type"
    );
    assert_non_empty(&problem.code, action, "code");
    assert_non_empty(&problem.title, action, "title");
    assert_non_empty(&problem.detail, action, "detail");

    Ok(problem)
}

fn assert_non_empty(value: &str, action: &str, field: &str) {
    assert!(
        !value.trim().is_empty(),
        "{action}: problem response field {field} was missing or empty"
    );
}
