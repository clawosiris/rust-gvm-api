// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{anyhow, Context, Result};
use gvm_gateway_e2e::harness::{
    E2eHarness, ListResponse, PortList, ScanConfig, Scanner, SessionResponse, Target, Task,
};

// Covers the target lifecycle contract clients rely on before creating scans.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_creates_lists_and_deletes_target() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let target_name = harness.unique_name("nightly-discovery-target");
        let target = harness
            .create_target(&session.token, &target_name, &resources.port_list.id)
            .await?;
        target_id = Some(target.id.clone());
        eprintln!(
            "created target {} ({}) for host(s) {}",
            target.name,
            target.id,
            target.hosts.join(", ")
        );

        assert_created_target(&harness, &target, &target_name, &resources.port_list);
        let targets = harness.list_targets(&session.token).await?;
        assert_target_list_contains(&targets, &target);

        harness.delete_target(&session.token, &target.id).await?;
        target_id = None;
        assert_target_not_listed(&harness, &session.token, &target.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(&harness, &session.token, None, target_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers task create/get/list/delete around the discovery scan prerequisites without starting a scan.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_creates_lists_and_deletes_task() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let tasks = harness.list_tasks(&session.token).await?;
        assert_task_list_contains(&tasks, &created.task);

        harness
            .delete_task(&session.token, &created.task.id)
            .await?;
        task_id = None;
        assert_task_not_listed(&harness, &session.token, &created.task.id).await?;

        harness
            .delete_target(&session.token, &created.target.id)
            .await?;
        target_id = None;
        assert_target_not_listed(&harness, &session.token, &created.target.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_cleanup(
            &harness,
            &session.token,
            task_id.as_deref(),
            target_id.as_deref(),
        )
        .await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the started scan contract: start-task returns a report id, completion links it, and report results are readable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_discovery_lifecycle_completes_scan_and_links_report() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut task_id = None;
    let mut target_id = None;

    let run = async {
        let resources = select_discovery_resources(&harness, &session.token).await?;
        let created = create_discovery_task(&harness, &session.token, &resources).await?;
        task_id = Some(created.task.id.clone());
        target_id = Some(created.target.id.clone());

        let action = harness.start_task(&session.token, &created.task.id).await?;
        assert!(
            !action.report_id.is_empty(),
            "start-task response did not include a report id"
        );
        eprintln!(
            "started task {}; report {}",
            created.task.id, action.report_id
        );

        let completed = harness
            .wait_for_task_completion(&session.token, &created.task.id)
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
            Some(created.task.id.as_str()),
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

    best_effort_cleanup(
        &harness,
        &session.token,
        task_id.as_deref(),
        target_id.as_deref(),
    )
    .await;
    finish_session(&harness, &session, run).await
}

struct DiscoveryResources {
    scan_config: ScanConfig,
    scanner: Scanner,
    port_list: PortList,
}

struct CreatedDiscoveryTask {
    target: Target,
    task: Task,
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

async fn select_discovery_resources(
    harness: &E2eHarness,
    token: &str,
) -> Result<DiscoveryResources> {
    let scan_configs = harness.list_scan_configs(token).await?;
    let scan_config = harness.select_discovery_scan_config(&scan_configs)?.clone();
    eprintln!(
        "selected discovery scan config {} ({})",
        scan_config.name, scan_config.id
    );

    let scanners = harness.list_scanners(token).await?;
    let scanner = harness.select_scanner(&scanners)?.clone();
    eprintln!("selected scanner {} ({})", scanner.name, scanner.id);

    // Real gvmd requires a target to carry a concrete port list before a task
    // can run, so the E2E suite proves the same contract real clients use.
    let port_lists = harness.list_port_lists(token).await?;
    let port_list = harness.select_port_list(&port_lists)?.clone();
    eprintln!("selected port list {} ({})", port_list.name, port_list.id);

    Ok(DiscoveryResources {
        scan_config,
        scanner,
        port_list,
    })
}

async fn create_discovery_task(
    harness: &E2eHarness,
    token: &str,
    resources: &DiscoveryResources,
) -> Result<CreatedDiscoveryTask> {
    let target_name = harness.unique_name("nightly-discovery-target");
    let target = harness
        .create_target(token, &target_name, &resources.port_list.id)
        .await?;
    eprintln!(
        "created target {} ({}) for host(s) {}",
        target.name,
        target.id,
        target.hosts.join(", ")
    );
    assert_created_target(harness, &target, &target_name, &resources.port_list);

    let task_name = harness.unique_name("nightly-discovery-task");
    let task = harness
        .create_task(
            token,
            &task_name,
            &target.id,
            &resources.scan_config.id,
            &resources.scanner.id,
        )
        .await?;
    eprintln!("created task {} ({})", task.name, task.id);
    assert_created_task(&task, &task_name, &target, resources);

    Ok(CreatedDiscoveryTask { target, task })
}

fn assert_created_target(
    harness: &E2eHarness,
    target: &Target,
    expected_name: &str,
    port_list: &PortList,
) {
    assert_eq!(target.name, expected_name);
    assert!(
        target
            .hosts
            .iter()
            .any(|host| host == &harness.config.target_host),
        "created target did not include configured host {}",
        harness.config.target_host
    );
    if let Some(actual_port_list) = target.port_list.as_ref() {
        assert_eq!(
            actual_port_list.id, port_list.id,
            "created target did not reference the selected port list"
        );
    }
}

fn assert_created_task(
    task: &Task,
    expected_name: &str,
    target: &Target,
    resources: &DiscoveryResources,
) {
    assert_eq!(task.name, expected_name);
    assert!(
        matches!(
            task.status.as_str(),
            "New" | "Requested" | "Running" | "Done"
        ),
        "created task returned unexpected lifecycle status {}",
        task.status
    );
    if let Some(actual_target) = task.target.as_ref() {
        assert_eq!(
            actual_target.id, target.id,
            "created task did not reference the created target"
        );
    }
    if let Some(actual_config) = task.scan_config.as_ref() {
        assert_eq!(
            actual_config.id, resources.scan_config.id,
            "created task did not reference the selected scan config"
        );
    }
    if let Some(actual_scanner) = task.scanner.as_ref() {
        assert_eq!(
            actual_scanner.id, resources.scanner.id,
            "created task did not reference the selected scanner"
        );
    }
}

fn assert_target_list_contains(targets: &ListResponse<Target>, target: &Target) {
    assert!(
        targets
            .data
            .iter()
            .any(|listed| listed.id == target.id && listed.name == target.name),
        "target list did not include created target {} ({})",
        target.name,
        target.id
    );
}

fn assert_task_list_contains(tasks: &ListResponse<Task>, task: &Task) {
    assert!(
        tasks
            .data
            .iter()
            .any(|listed| listed.id == task.id && listed.name == task.name),
        "task list did not include created task {} ({})",
        task.name,
        task.id
    );
}

async fn assert_target_not_listed(
    harness: &E2eHarness,
    token: &str,
    target_id: &str,
) -> Result<()> {
    let targets = harness
        .list_targets(token)
        .await
        .context("list targets after deleting target")?;
    assert!(
        targets.data.iter().all(|target| target.id != target_id),
        "deleted target {target_id} was still returned by list targets"
    );
    Ok(())
}

async fn assert_task_not_listed(harness: &E2eHarness, token: &str, task_id: &str) -> Result<()> {
    let tasks = harness
        .list_tasks(token)
        .await
        .context("list tasks after deleting task")?;
    assert!(
        tasks.data.iter().all(|task| task.id != task_id),
        "deleted task {task_id} was still returned by list tasks"
    );
    Ok(())
}

async fn best_effort_cleanup(
    harness: &E2eHarness,
    token: &str,
    task_id: Option<&str>,
    target_id: Option<&str>,
) {
    if let Some(task_id) = task_id {
        if let Err(error) = harness.delete_task(token, task_id).await {
            eprintln!("best-effort task cleanup failed for {task_id}: {error:#}");
        }
    }
    if let Some(target_id) = target_id {
        if let Err(error) = harness.delete_target(token, target_id).await {
            eprintln!("best-effort target cleanup failed for {target_id}: {error:#}");
        }
    }
}
