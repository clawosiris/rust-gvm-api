// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{anyhow, Context, Result};
use gvm_gateway_e2e::harness::{
    E2eHarness, ListResponse, PortList, Report, ResultList, ScanConfig, ScanResult, Scanner,
    SessionResponse, Target, Task,
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

// Covers the started scan and report drill-down contract around the report produced by a completed task.
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

        let reports = harness.list_reports(&session.token).await?;
        assert_report_list_contains(&reports, &report, &created.task);

        let first_results_page = harness
            .get_report_results_page(&session.token, &action.report_id, 1, 1)
            .await?;
        assert_report_results_page_links_report(
            "report results",
            &first_results_page,
            &report,
            &created.task,
            Some(1),
        );
        assert_report_result_total_consistent("report results", &first_results_page, &report);

        let vulnerabilities = harness
            .get_report_vulnerabilities_page(&session.token, &action.report_id, 1, 25)
            .await?;
        assert_report_vulnerabilities_page_links_report(&vulnerabilities, &report, &created.task);

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

fn assert_report_list_contains(reports: &ListResponse<Report>, report: &Report, task: &Task) {
    assert_pagination_shape("reports", reports);
    let listed = reports
        .data
        .iter()
        .find(|listed| listed.id == report.id)
        .unwrap_or_else(|| panic!("report list did not include completed report {}", report.id));
    assert_eq!(
        listed.task.as_ref().map(|task| task.id.as_str()),
        Some(task.id.as_str()),
        "listed report did not point back to the completed task"
    );
}

fn assert_report_results_page_links_report(
    resource: &str,
    page: &ResultList,
    report: &Report,
    task: &Task,
    expected_per_page: Option<u32>,
) {
    assert_result_pagination_shape(resource, page, expected_per_page);

    for result in &page.data {
        assert_scan_result_links_report(resource, result, report, task);
    }
}

fn assert_report_vulnerabilities_page_links_report(
    page: &ResultList,
    report: &Report,
    task: &Task,
) {
    assert_report_results_page_links_report("report vulnerabilities", page, report, task, Some(25));

    if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
        assert!(
            page.pagination.total <= total,
            "vulnerability total {} exceeded report total {}",
            page.pagination.total,
            total
        );
    }

    for result in &page.data {
        assert!(
            result.nvt.is_some() || result.severity.is_some() || !result.name.trim().is_empty(),
            "vulnerability result {} did not expose finding metadata",
            result.id
        );
    }
}

fn assert_scan_result_links_report(
    resource: &str,
    result: &ScanResult,
    report: &Report,
    task: &Task,
) {
    assert!(
        !result.id.trim().is_empty(),
        "{resource} returned a result with an empty id"
    );
    assert!(
        !result.name.trim().is_empty(),
        "{resource} returned result {} with an empty name",
        result.id
    );
    if let Some(result_report) = result.report.as_ref() {
        assert_eq!(
            result_report.id, report.id,
            "{resource} result {} did not point back to report {}",
            result.id, report.id
        );
    }
    if let Some(result_task) = result.task.as_ref() {
        assert_eq!(
            result_task.id, task.id,
            "{resource} result {} did not point back to task {}",
            result.id, task.id
        );
    }
}

fn assert_report_result_total_consistent(resource: &str, page: &ResultList, report: &Report) {
    if let Some(total) = report.result_count.as_ref().and_then(|count| count.total) {
        assert!(
            page.pagination.total >= total || page.data.len() as u32 >= total,
            "{resource} pagination under-reported total results"
        );
    }
}

fn assert_result_pagination_shape(
    resource: &str,
    response: &ResultList,
    expected_per_page: Option<u32>,
) {
    assert_eq!(
        response.pagination.page, 1,
        "{resource} list used an unexpected page"
    );
    if let Some(expected_per_page) = expected_per_page {
        assert_eq!(
            response.pagination.per_page, expected_per_page,
            "{resource} list used an unexpected page size"
        );
    } else {
        assert!(
            response.pagination.per_page > 0,
            "{resource} list returned a non-positive page size"
        );
    }
    if response.pagination.total == 0 {
        assert_eq!(
            response.pagination.total_pages, 0,
            "{resource} list returned totalPages for an empty result set"
        );
    } else {
        assert!(
            response.pagination.total_pages >= 1,
            "{resource} list returned no pages for a non-empty result set"
        );
    }
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
    );
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
    if response.pagination.total == 0 {
        assert_eq!(
            response.pagination.total_pages, 0,
            "{resource} list returned totalPages for an empty result set"
        );
    } else {
        assert!(
            response.pagination.total_pages >= 1,
            "{resource} list returned no pages for a non-empty result set"
        );
    }
    assert!(
        response.data.len() <= response.pagination.per_page as usize,
        "{resource} list returned more items than its page size"
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
