// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{anyhow, Result};
use gvm_gateway_e2e::harness::E2eHarness;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_scan_happy_path() -> Result<()> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;

    let session = harness.create_session().await?;
    eprintln!(
        "created session; gmpVersion={} expiresIn={}s",
        session.gmp_version, session.expires_in
    );

    let run = async {
        let scan_configs = harness.list_scan_configs(&session.token).await?;
        let scan_config = harness.select_discovery_scan_config(&scan_configs)?;
        eprintln!(
            "selected discovery scan config {} ({})",
            scan_config.name, scan_config.id
        );

        let scanners = harness.list_scanners(&session.token).await?;
        let scanner = harness.select_scanner(&scanners)?;
        eprintln!("selected scanner {} ({})", scanner.name, scanner.id);

        // Real gvmd requires a target to carry a concrete port list before a
        // task can run; this keeps the end-to-end path on the production GMP
        // contract instead of relying on static-adapter defaults.
        let port_lists = harness.list_port_lists(&session.token).await?;
        let port_list = harness.select_port_list(&port_lists)?;
        eprintln!("selected port list {} ({})", port_list.name, port_list.id);

        let target_name = harness.unique_name("nightly-discovery-target");
        let target = harness
            .create_target(&session.token, &target_name, &port_list.id)
            .await?;
        eprintln!(
            "created target {} ({}) for host(s) {}",
            target.name,
            target.id,
            target.hosts.join(", ")
        );

        let task_name = harness.unique_name("nightly-discovery-task");
        let task = harness
            .create_task(
                &session.token,
                &task_name,
                &target.id,
                &scan_config.id,
                &scanner.id,
            )
            .await?;
        eprintln!("created task {} ({})", task.name, task.id);

        let action = harness.start_task(&session.token, &task.id).await?;
        eprintln!("started task {}; report {}", task.id, action.report_id);

        let completed = harness
            .wait_for_task_completion(&session.token, &task.id)
            .await?;
        let report_ref = completed
            .last_report
            .as_ref()
            .or(completed.current_report.as_ref())
            .ok_or_else(|| {
                anyhow!(
                    "completed task {} did not expose a report reference",
                    completed.id
                )
            })?;
        assert_eq!(
            report_ref.id, action.report_id,
            "task report reference drifted from start-task response"
        );

        let report = harness
            .get_report(&session.token, &action.report_id)
            .await?;
        assert_eq!(report.id, action.report_id);
        assert_eq!(
            report.task.as_ref().map(|task| task.id.as_str()),
            Some(task.id.as_str()),
            "report did not point back to the created task"
        );
        assert!(
            report.scan_end.is_some(),
            "completed report {} was missing scanEnd",
            report.id
        );
        eprintln!(
            "report {} scanEnd={:?} resultCount={:?}",
            report.id, report.scan_end, report.result_count
        );

        let report_results = harness
            .get_report_results(&session.token, &action.report_id)
            .await?;
        eprintln!(
            "report results page={} perPage={} total={} items={}",
            report_results.pagination.page,
            report_results.pagination.per_page,
            report_results.pagination.total,
            report_results.data.len()
        );

        if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
            assert!(
                report_results.pagination.total >= total
                    || report_results.data.len() as u32 >= total,
                "report result pagination under-reported total results"
            );
        }

        Ok(())
    }
    .await;

    if let Err(error) = harness.delete_session(&session.token).await {
        eprintln!("best-effort session cleanup failed: {error:#}");
    }

    run
}
