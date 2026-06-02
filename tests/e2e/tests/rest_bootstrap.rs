// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::Result;
use gvm_gateway_e2e::harness::E2eHarness;

// Covers the live-stack public bootstrap contract because operators and later
// E2E scenarios depend on stable liveness, readiness, and version endpoints
// before authenticated resource workflows can be diagnosed meaningfully.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_bootstrap_public_endpoints_report_live_ready_versioned_gateway() -> Result<()> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;

    let health = harness.get_health().await?;
    assert_eq!(
        health.status, "ok",
        "health endpoint did not report process liveness"
    );

    let readiness = harness.get_readiness().await?;
    assert_eq!(
        readiness.status, "ready",
        "readiness endpoint did not report a ready gateway"
    );
    assert!(
        readiness
            .reason
            .as_deref()
            .is_none_or(|reason| !reason.trim().is_empty()),
        "readiness endpoint returned an empty reason"
    );

    let version = harness.get_version().await?;
    assert!(
        !version.api_version.trim().is_empty(),
        "version endpoint returned an empty API version"
    );
    assert!(
        !version.gmp_version.trim().is_empty(),
        "version endpoint returned an empty GMP version"
    );

    Ok(())
}
