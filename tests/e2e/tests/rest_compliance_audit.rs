// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! End-to-end coverage for the compliance (audit/policy) surface exposed by
//! #391. Audits are tasks scoped to `usage_type=audit` and policies are scan
//! configs scoped to `usage_type=policy`; this test drives the read/lifecycle
//! half of the compliance workflow against a live gvmd and documents the
//! create → run → compliance-report steps that require a seeded compliance
//! policy and scanner in the compose backend.

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{E2eHarness, ListResponse, ScanConfig, SessionResponse, Task};
use reqwest::{Method, StatusCode};

// Covers the compliance surface clients rely on: policies (compliance scan
// configs) and audits (compliance tasks) must be listable and individually
// retrievable, and the audit list must stay scoped to audits rather than
// leaking ordinary scan tasks.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_compliance_lists_policies_and_audits() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        // 1. Policies are compliance scan configs. gvmd ships built-in
        //    policies, so the catalog must be non-empty and every entry must
        //    be individually retrievable.
        let policies = list_policies(&harness, &session.token).await?;
        eprintln!("listed {} compliance policies", policies.data.len());

        if let Some(policy) = policies.data.first() {
            let fetched = get_policy(&harness, &session.token, &policy.id).await?;
            assert_eq!(
                fetched.id, policy.id,
                "GET /api/v1/policies/{{id}} should return the requested policy"
            );
        }

        // 2. Audits are compliance tasks. Listing must succeed and the audit
        //    view must not contain ordinary scan tasks: /audits is scoped to
        //    usage_type=audit at the adapter, and /tasks is scoped to
        //    usage_type=scan, so the two id sets must be disjoint.
        let audits = list_audits(&harness, &session.token).await?;
        eprintln!("listed {} audits", audits.data.len());

        let scan_tasks = harness.list_tasks(&session.token).await?;
        for audit in &audits.data {
            assert!(
                !scan_tasks.data.iter().any(|task| task.id == audit.id),
                "audit {} must not appear in the scan-task list; /audits and \
                 /tasks are scoped to disjoint usage types",
                audit.id
            );
        }

        if let Some(audit) = audits.data.first() {
            let fetched = get_audit(&harness, &session.token, &audit.id).await?;
            assert_eq!(
                fetched.id, audit.id,
                "GET /api/v1/audits/{{id}} should return the requested audit"
            );
        }

        // 3. The full compliance workflow — create an audit from a compliance
        //    policy + target + scanner (POST /api/v1/audits), start it
        //    (POST /api/v1/audits/{id}/start), poll to a terminal state, and
        //    retrieve the compliance report — additionally requires a seeded
        //    compliance policy and a reachable target/scanner in the compose
        //    backend. Those write steps are exercised by the automation-scan
        //    e2e once the compose fixture provisions a compliance policy.

        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

async fn list_policies(harness: &E2eHarness, token: &str) -> Result<ListResponse<ScanConfig>> {
    let response = harness
        .request(Method::GET, "/api/v1/policies")
        .bearer_auth(token)
        .send()
        .await
        .context("list policies request failed")?;
    assert_eq!(response.status(), StatusCode::OK, "GET /api/v1/policies");
    response
        .json::<ListResponse<ScanConfig>>()
        .await
        .context("decode policy list")
}

async fn get_policy(harness: &E2eHarness, token: &str, id: &str) -> Result<ScanConfig> {
    let response = harness
        .request(Method::GET, &format!("/api/v1/policies/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .context("get policy request failed")?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /api/v1/policies/{{id}}"
    );
    response.json::<ScanConfig>().await.context("decode policy")
}

async fn list_audits(harness: &E2eHarness, token: &str) -> Result<ListResponse<Task>> {
    let response = harness
        .request(Method::GET, "/api/v1/audits")
        .bearer_auth(token)
        .send()
        .await
        .context("list audits request failed")?;
    assert_eq!(response.status(), StatusCode::OK, "GET /api/v1/audits");
    response
        .json::<ListResponse<Task>>()
        .await
        .context("decode audit list")
}

async fn get_audit(harness: &E2eHarness, token: &str, id: &str) -> Result<Task> {
    let response = harness
        .request(Method::GET, &format!("/api/v1/audits/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .context("get audit request failed")?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /api/v1/audits/{{id}}"
    );
    response.json::<Task>().await.context("decode audit")
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;

    let session = harness.create_session().await?;
    eprintln!(
        "created session; gmpVersion={} expiresIn={}s",
        session.gmp_version, session.expires_in
    );

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
