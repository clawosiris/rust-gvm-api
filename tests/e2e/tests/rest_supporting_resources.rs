// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{
    CreatedResource, Credential, E2eHarness, ListResponse, PortList, ScanConfig, SessionResponse,
};

// Covers stable list/read contracts for supporting catalogs used by setup and discovery flows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_catalogs_list_and_read_resources() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        assert_scan_config_catalog(&harness, &session.token).await?;
        assert_scanner_catalog(&harness, &session.token).await?;
        assert_port_list_catalog(&harness, &session.token).await?;
        assert_feed_catalog(&harness, &session.token).await?;
        assert_timezone_catalog(&harness, &session.token).await?;
        assert_credential_store_catalog(&harness, &session.token).await?;
        assert_credential_list_shape(&harness, &session.token).await?;
        assert_report_format_catalog(&harness, &session.token).await?;
        assert_filter_catalog(&harness, &session.token).await?;
        assert_tag_catalog(&harness, &session.token).await?;
        assert_ticket_catalog(&harness, &session.token).await?;
        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

// Covers scan-config copy/update/delete against gvmd because scan configs are
// created by copying an existing base config rather than by building one blank.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_scan_config_lifecycle_copies_updates_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut scan_config_id = None;

    let run = async {
        let scan_configs = harness.list_scan_configs(&session.token).await?;
        let base_config = harness.select_discovery_scan_config(&scan_configs)?;
        let scan_config_name = harness.unique_name("nightly-supporting-scan-config");
        let created_comment = "created by compose-backed E2E scan-config coverage";
        let created = harness
            .create_scan_config_from_base(
                &session.token,
                &scan_config_name,
                created_comment,
                &base_config.id,
            )
            .await?;
        assert_created_location(&created, "/api/v1/scan-configs");
        scan_config_id = Some(created.id.clone());

        let scan_config = harness.get_scan_config(&session.token, &created.id).await?;
        assert_scan_config_matches_created(&scan_config, &created.id, &scan_config_name);

        let updated_comment = "updated by compose-backed E2E scan-config coverage";
        let updated = harness
            .update_scan_config_comment(&session.token, &created.id, updated_comment)
            .await?;
        assert_eq!(
            updated.id, created.id,
            "scan-config id changed after update"
        );
        assert_eq!(
            updated.comment.as_deref(),
            Some(updated_comment),
            "scan-config update response did not expose changed comment"
        );
        let fetched = harness.get_scan_config(&session.token, &created.id).await?;
        assert_eq!(
            fetched.comment.as_deref(),
            Some(updated_comment),
            "scan-config read after update did not preserve changed comment"
        );

        harness
            .delete_scan_config(&session.token, &created.id)
            .await?;
        scan_config_id = None;
        assert_scan_config_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_scan_config(&harness, &session.token, scan_config_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the port-list create/read/list/delete contract with a small repeatable payload.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_port_list_lifecycle_creates_reads_lists_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut port_list_id = None;

    let run = async {
        let port_list_name = harness.unique_name("nightly-supporting-port-list");
        let created = harness
            .create_port_list(&session.token, &port_list_name, "T:1")
            .await?;
        assert_created_location(&created, "/api/v1/port-lists");
        port_list_id = Some(created.id.clone());

        let port_list = harness.get_port_list(&session.token, &created.id).await?;
        assert_port_list_matches_created(&port_list, &created.id, &port_list_name);

        let port_lists = harness.list_port_lists(&session.token).await?;
        assert!(
            port_lists
                .iter()
                .any(|listed| listed.id == created.id && listed.name == port_list_name),
            "created port list {} ({}) was not returned by list port lists",
            port_list_name,
            created.id
        );

        harness
            .delete_port_list(&session.token, &created.id)
            .await?;
        port_list_id = None;
        assert_port_list_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_port_list(&harness, &session.token, port_list_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

// Covers the credential create/read/list/delete contract using the least environment-sensitive type.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_supporting_credential_lifecycle_creates_reads_lists_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut credential_id = None;

    let run = async {
        let credential_name = harness.unique_name("nightly-supporting-credential");
        let created = harness
            .create_username_password_credential(
                &session.token,
                &credential_name,
                "nightly-user",
                "nightly-password",
            )
            .await?;
        assert_created_location(&created, "/api/v1/credentials");
        credential_id = Some(created.id.clone());

        let credential = harness.get_credential(&session.token, &created.id).await?;
        assert_credential_matches_created(&credential, &created.id, &credential_name);

        let credentials = harness.list_credentials(&session.token).await?;
        assert!(
            credentials
                .data
                .iter()
                .any(|listed| listed.id == created.id && listed.name == credential_name),
            "created credential {} ({}) was not returned by list credentials",
            credential_name,
            created.id
        );

        harness
            .delete_credential(&session.token, &created.id)
            .await?;
        credential_id = None;
        assert_credential_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_credential(&harness, &session.token, credential_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
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

async fn assert_scan_config_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let scan_configs = harness.list_scan_configs(token).await?;
    let selected = harness.select_discovery_scan_config(&scan_configs)?;
    let fetched = harness.get_scan_config(token, &selected.id).await?;
    assert_named_resource_matches(
        "scan config",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_scanner_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let scanners = harness.list_scanners(token).await?;
    let selected = harness.select_scanner(&scanners)?;
    let fetched = harness.get_scanner(token, &selected.id).await?;
    assert_named_resource_matches(
        "scanner",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_port_list_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let port_lists = harness.list_port_lists(token).await?;
    let selected = harness.select_port_list(&port_lists)?;
    let fetched = harness.get_port_list(token, &selected.id).await?;
    assert_named_resource_matches(
        "port list",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    Ok(())
}

async fn assert_feed_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let feeds = harness.list_feeds(token).await?;
    assert!(
        !feeds.is_empty(),
        "feed status did not return any feed entries"
    );
    for feed in feeds {
        assert!(
            !feed.feed_type.trim().is_empty(),
            "feed entry returned an empty type"
        );
        assert!(
            !feed.name.trim().is_empty(),
            "feed entry returned an empty name"
        );
    }
    Ok(())
}

async fn assert_timezone_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let timezones = harness.list_timezones(token).await?;
    assert!(
        !timezones.is_empty(),
        "timezone catalog did not return any entries"
    );
    assert!(
        timezones
            .iter()
            .any(|timezone| !timezone.name.trim().is_empty()),
        "timezone catalog returned only empty names"
    );
    Ok(())
}

async fn assert_credential_store_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let stores = harness.list_credential_stores(token).await?;
    for store in stores {
        assert!(
            !store.id.trim().is_empty(),
            "credential store returned an empty id"
        );
        assert!(
            !store.name.trim().is_empty(),
            "credential store returned an empty name"
        );
    }
    Ok(())
}

async fn assert_credential_list_shape(harness: &E2eHarness, token: &str) -> Result<()> {
    let credentials = harness.list_credentials(token).await?;
    assert_pagination_shape("credentials", &credentials);
    for credential in credentials.data {
        assert!(
            !credential.id.trim().is_empty(),
            "credential list returned an empty id"
        );
        assert!(
            !credential.name.trim().is_empty(),
            "credential list returned an empty name"
        );
    }
    Ok(())
}

async fn assert_report_format_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let report_formats = harness.list_report_formats(token).await?;
    assert_pagination_shape("report formats", &report_formats);
    assert!(
        !report_formats.data.is_empty(),
        "report-format catalog did not return any entries"
    );
    let selected = harness.select_report_format_by_extension(
        &report_formats.data,
        "pdf",
        Some(&harness.config.pdf_report_format_id),
    )?;
    let fetched = harness.get_report_format(token, &selected.id).await?;
    assert_named_resource_matches(
        "report format",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.extension, selected.extension,
        "report format extension drifted on read"
    );
    Ok(())
}

async fn assert_filter_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let filters = harness.list_filters(token).await?;
    assert_pagination_shape("filters", &filters);
    let Some(selected) = filters.data.first() else {
        eprintln!("filter catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_filter(token, &selected.id).await?;
    assert_named_resource_matches(
        "filter",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.filter_type, selected.filter_type,
        "filter type drifted on read"
    );
    Ok(())
}

async fn assert_tag_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let tags = harness.list_tags(token).await?;
    assert_pagination_shape("tags", &tags);
    let Some(selected) = tags.data.first() else {
        eprintln!("tag catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_tag(token, &selected.id).await?;
    assert_named_resource_matches(
        "tag",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(fetched.value, selected.value, "tag value drifted on read");
    Ok(())
}

async fn assert_ticket_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let tickets = harness.list_tickets(token).await?;
    assert_pagination_shape("tickets", &tickets);
    let Some(selected) = tickets.data.first() else {
        eprintln!("ticket catalog is empty; skipping item read assertion");
        return Ok(());
    };

    let fetched = harness.get_ticket(token, &selected.id).await?;
    assert_named_resource_matches(
        "ticket",
        &fetched.id,
        &fetched.name,
        &selected.id,
        &selected.name,
    );
    assert_eq!(
        fetched.status, selected.status,
        "ticket status drifted on read"
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

fn assert_named_resource_matches(
    resource: &str,
    actual_id: &str,
    actual_name: &str,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(actual_id, expected_id, "{resource} id drifted on read");
    assert_eq!(
        actual_name, expected_name,
        "{resource} name drifted on read"
    );
}

fn assert_created_location(created: &CreatedResource, collection_path: &str) {
    assert!(
        created
            .location
            .ends_with(&format!("{collection_path}/{}", created.id)),
        "created resource Location {} did not point at returned id {}",
        created.location,
        created.id
    );
}

fn assert_port_list_matches_created(port_list: &PortList, expected_id: &str, expected_name: &str) {
    assert_eq!(port_list.id, expected_id);
    assert_eq!(port_list.name, expected_name);
}

fn assert_scan_config_matches_created(
    scan_config: &ScanConfig,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(scan_config.id, expected_id);
    assert_eq!(scan_config.name, expected_name);
}

fn assert_credential_matches_created(
    credential: &Credential,
    expected_id: &str,
    expected_name: &str,
) {
    assert_eq!(credential.id, expected_id);
    assert_eq!(credential.name, expected_name);
    assert_eq!(
        credential.credential_type.as_deref(),
        Some("up"),
        "created credential did not preserve username/password type"
    );
    assert_eq!(
        credential.login.as_deref(),
        Some("nightly-user"),
        "created credential did not preserve login"
    );
}

async fn assert_scan_config_not_listed(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: &str,
) -> Result<()> {
    let scan_configs = harness
        .list_scan_configs(token)
        .await
        .context("list scan configs after deleting scan config")?;
    assert!(
        scan_configs
            .iter()
            .all(|scan_config| scan_config.id != scan_config_id),
        "deleted scan config {scan_config_id} was still returned by list scan configs"
    );
    Ok(())
}

async fn assert_port_list_not_listed(
    harness: &E2eHarness,
    token: &str,
    port_list_id: &str,
) -> Result<()> {
    let port_lists = harness
        .list_port_lists(token)
        .await
        .context("list port lists after deleting port list")?;
    assert!(
        port_lists
            .iter()
            .all(|port_list| port_list.id != port_list_id),
        "deleted port list {port_list_id} was still returned by list port lists"
    );
    Ok(())
}

async fn assert_credential_not_listed(
    harness: &E2eHarness,
    token: &str,
    credential_id: &str,
) -> Result<()> {
    let credentials = harness
        .list_credentials(token)
        .await
        .context("list credentials after deleting credential")?;
    assert!(
        credentials
            .data
            .iter()
            .all(|credential| credential.id != credential_id),
        "deleted credential {credential_id} was still returned by list credentials"
    );
    Ok(())
}

async fn best_effort_delete_scan_config(
    harness: &E2eHarness,
    token: &str,
    scan_config_id: Option<&str>,
) {
    if let Some(scan_config_id) = scan_config_id {
        if let Err(error) = harness.delete_scan_config(token, scan_config_id).await {
            eprintln!("best-effort scan-config cleanup failed for {scan_config_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_port_list(
    harness: &E2eHarness,
    token: &str,
    port_list_id: Option<&str>,
) {
    if let Some(port_list_id) = port_list_id {
        if let Err(error) = harness.delete_port_list(token, port_list_id).await {
            eprintln!("best-effort port-list cleanup failed for {port_list_id}: {error:#}");
        }
    }
}

async fn best_effort_delete_credential(
    harness: &E2eHarness,
    token: &str,
    credential_id: Option<&str>,
) {
    if let Some(credential_id) = credential_id {
        if let Err(error) = harness.delete_credential(token, credential_id).await {
            eprintln!("best-effort credential cleanup failed for {credential_id}: {error:#}");
        }
    }
}
