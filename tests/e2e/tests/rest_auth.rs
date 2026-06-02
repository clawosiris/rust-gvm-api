// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{assert_problem_response_any, E2eHarness, ListResponse, Target};
use reqwest::StatusCode;

// Covers live-stack authentication failures and session invalidation because
// the gateway's REST auth boundary must reject unauthenticated, unknown, and
// explicitly closed credentials before proxying protected work to gvmd.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_auth_contract_rejects_invalid_and_closed_sessions() -> Result<()> {
    let harness = ready_harness().await?;

    assert_status(
        harness.get_targets_without_auth().await?,
        StatusCode::UNAUTHORIZED,
        "missing auth on protected route",
    )
    .await?;

    assert_status(
        harness
            .create_session_with_credentials(
                &harness.config.username,
                &format!("{}-wrong", harness.config.password),
            )
            .await?,
        StatusCode::UNAUTHORIZED,
        "invalid Basic credentials on session creation",
    )
    .await?;

    assert_status(
        harness.get_targets_with_bearer("gvm_sess_unknown").await?,
        StatusCode::UNAUTHORIZED,
        "unknown bearer token on protected route",
    )
    .await?;

    let session = harness.create_session().await?;
    harness.delete_session(&session.token).await?;

    assert_status(
        harness.get_targets_with_bearer(&session.token).await?,
        StatusCode::UNAUTHORIZED,
        "deleted bearer token on protected route",
    )
    .await
}

// Covers the single-call Basic auth contract so clients can use one protected
// request without creating a durable session token, while the gateway still
// rejects a follow-up request that carries no credentials.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_request_scoped_basic_auth_lists_targets_without_persistent_session() -> Result<()> {
    let harness = ready_harness().await?;

    let response = harness
        .get_targets_with_basic(&harness.config.username, &harness.config.password)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let targets = response
        .json::<ListResponse<Target>>()
        .await
        .context("parse request-scoped Basic target list")?;
    assert_pagination_shape("targets", &targets);

    assert_status(
        harness.get_targets_without_auth().await?,
        StatusCode::UNAUTHORIZED,
        "protected route after request-scoped Basic call without credentials",
    )
    .await
}

// Covers session create/read/close semantics so persistent-session clients can
// rely on Location, session metadata, and malformed Basic auth rejection.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_session_lifecycle_exposes_location_and_session_details() -> Result<()> {
    let harness = ready_harness().await?;

    let created = harness.create_session_with_location().await?;
    assert!(
        created
            .location
            .ends_with(&format!("/api/v1/sessions/{}", created.session.token)),
        "session Location {} did not point at returned token",
        created.location
    );
    assert!(
        !created.session.token.trim().is_empty(),
        "created session returned an empty token"
    );
    assert!(
        created.session.expires_in > 0,
        "created session returned a non-positive expiry"
    );
    assert!(
        !created.session.gmp_version.trim().is_empty(),
        "created session returned an empty GMP version"
    );

    let session = harness.get_session(&created.session.token).await?;
    assert_eq!(
        session.token, created.session.token,
        "session read returned a different token"
    );
    assert_eq!(
        session.user, harness.config.username,
        "session read returned an unexpected user"
    );
    assert!(
        matches!(session.state.as_str(), "active" | "idle"),
        "session read returned unexpected state {}",
        session.state
    );
    assert!(
        !session.created_at.trim().is_empty() && !session.last_used_at.trim().is_empty(),
        "session read did not include timestamps"
    );
    assert!(
        session.expires_in >= 0,
        "session read returned a negative expiry"
    );

    let malformed = harness.create_session_with_malformed_basic().await?;
    assert_problem_response_any(
        malformed,
        &[StatusCode::UNAUTHORIZED],
        "malformed Basic session creation",
    )
    .await?;

    harness.delete_session(&created.session.token).await?;
    let deleted = harness.get_session_response(&created.session.token).await?;
    assert_problem_response_any(
        deleted,
        &[StatusCode::NOT_FOUND, StatusCode::UNAUTHORIZED],
        "deleted session read",
    )
    .await?;

    Ok(())
}

async fn ready_harness() -> Result<E2eHarness> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    Ok(harness)
}

async fn assert_status(
    response: reqwest::Response,
    expected: StatusCode,
    action: &str,
) -> Result<()> {
    let status = response.status();
    let body = response.text().await.context("read response body")?;
    assert_eq!(
        status, expected,
        "{action}: expected HTTP {expected} but received {status} with body {body}"
    );
    Ok(())
}

fn assert_pagination_shape<T>(resource: &str, response: &ListResponse<T>) {
    assert_eq!(
        response.pagination.page, 1,
        "{resource} list used an unexpected default page"
    );
    assert!(
        response.pagination.per_page > 0,
        "{resource} list returned a non-positive page size"
    );
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
    );
}
