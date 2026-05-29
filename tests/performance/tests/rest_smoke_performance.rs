// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::E2eHarness;
use gvm_gateway_performance::{log_report, measure_operation, persist_report, PerformanceConfig};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn list_port_lists_read_scenario() -> Result<()> {
    let harness = E2eHarness::from_env()?;
    let config = PerformanceConfig::from_env()?;
    harness.wait_until_ready().await?;

    let session = harness.create_session().await?;
    let run = async {
        let baseline_port_list = harness
            .select_port_list(&harness.list_port_lists(&session.token).await?)?
            .clone();
        let report = measure_operation(
            &config,
            "list-port-lists-read",
            "read",
            vec![
                "compose-backed seeded development stack".to_owned(),
                "single-threaded execution (`cargo test -- --test-threads=1`)".to_owned(),
                format!(
                    "stable seeded resource: port list {} ({})",
                    baseline_port_list.name, baseline_port_list.id
                ),
            ],
            || async {
                let port_lists = harness.list_port_lists(&session.token).await?;
                let selected = harness.select_port_list(&port_lists)?;
                anyhow::ensure!(
                    selected.id == baseline_port_list.id,
                    "selected port list drifted from seeded baseline"
                );
                Ok(())
            },
        )
        .await?;

        let path = persist_report(&config, &report)?;
        log_report(&report, &path);
        Ok(())
    }
    .await;

    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }

    run
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn create_and_delete_target_write_scenario() -> Result<()> {
    let harness = E2eHarness::from_env()?;
    let config = PerformanceConfig::from_env()?;
    harness.wait_until_ready().await?;

    let session = harness.create_session().await?;
    let run = async {
        let port_list = harness
            .select_port_list(&harness.list_port_lists(&session.token).await?)?
            .clone();
        let report = measure_operation(
            &config,
            "create-delete-target-write",
            "write",
            vec![
                "compose-backed seeded development stack".to_owned(),
                "single-threaded execution (`cargo test -- --test-threads=1`)".to_owned(),
                format!(
                    "write path uses target host {} and port list {} ({})",
                    harness.config.target_host, port_list.name, port_list.id
                ),
                "each iteration creates a fresh target and deletes it before the next sample"
                    .to_owned(),
            ],
            || async {
                let target_name = harness.unique_name("perf-target");
                let target = harness
                    .create_target(&session.token, &target_name, &port_list.id)
                    .await
                    .with_context(|| format!("create target {target_name}"))?;
                harness
                    .delete_target(&session.token, &target.id)
                    .await
                    .with_context(|| format!("delete target {}", target.id))?;
                Ok(())
            },
        )
        .await?;

        let path = persist_report(&config, &report)?;
        log_report(&report, &path);
        Ok(())
    }
    .await;

    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }

    run
}
