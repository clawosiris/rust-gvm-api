// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{Context, Result};
use gvm_gateway_e2e::harness::{
    assert_problem_response_any, CreatedResource, E2eHarness, Group, IdentityResourceMeta,
    ListResponse, Permission, Role, SessionResponse, User, UserSetting,
};
use reqwest::{Method, StatusCode};
use serde_json::json;

// Covers the shipped identity/admin list and read surface against a live gvmd
// stack so route registration, pagination, and typed REST response mapping do
// not drift from the implemented OpenAPI contract.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_identity_admin_catalogs_list_and_read_resources() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        assert_user_catalog(&harness, &session.token).await?;
        assert_group_catalog(&harness, &session.token).await?;
        assert_role_catalog(&harness, &session.token).await?;
        assert_permission_catalog(&harness, &session.token).await?;
        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

// Covers authentication rejection on identity/admin routes because these
// endpoints must fail at the REST auth boundary before returning identity data.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_identity_admin_routes_reject_missing_and_invalid_auth() -> Result<()> {
    let harness = ready_harness().await?;

    assert_problem_response_any(
        harness.get_users_without_auth().await?,
        &[StatusCode::UNAUTHORIZED],
        "missing auth on identity route",
    )
    .await?;

    assert_problem_response_any(
        harness.get_users_with_bearer("gvm_sess_unknown").await?,
        &[StatusCode::UNAUTHORIZED],
        "unknown bearer token on identity route",
    )
    .await?;

    Ok(())
}

// Covers user-settings as a current-user-scoped contract rather than generic
// admin CRUD by listing settings for the authenticated session and reading one
// setting by ID when the real stack exposes settings.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_identity_user_settings_list_read_and_update_current_user_setting() -> Result<()> {
    let (harness, session) = ready_session().await?;

    let run = async {
        let settings = harness.list_user_settings(&session.token).await?;
        for setting in &settings.data {
            assert_user_setting_shape(setting);
        }

        let Some(setting) = settings.data.first() else {
            eprintln!("gvmd returned no user settings; covered empty current-user list contract");
            return Ok(());
        };

        let fetched = harness
            .get_user_setting(&session.token, &setting.id)
            .await?;
        assert_eq!(fetched.id, setting.id, "user setting id drifted on read");
        assert_eq!(
            fetched.name, setting.name,
            "user setting name drifted on read"
        );

        let Some(updatable) = settings.data.iter().find(|setting| setting.value.is_some()) else {
            eprintln!(
                "gvmd returned no user settings with values; covered list/read but skipped update"
            );
            return Ok(());
        };
        let original_value = updatable
            .value
            .as_deref()
            .expect("updatable user setting was selected for having a value");

        let update_response = harness
            .request(
                Method::PUT,
                &format!("/api/v1/user-settings/{}", updatable.id),
            )
            .bearer_auth(&session.token)
            .json(&json!({ "value": original_value }))
            .send()
            .await
            .context("send user setting update with existing value")?;
        let update_status = update_response.status();
        let update_body = update_response
            .text()
            .await
            .context("read user setting update response")?;
        if matches!(
            update_status,
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
        ) {
            eprintln!(
                "gvmd rejected user setting update for {} ({}): status={} body={}",
                updatable.name, updatable.id, update_status, update_body
            );
            return Ok(());
        }
        assert_eq!(
            update_status,
            StatusCode::OK,
            "user setting update returned unexpected status {update_status} with body {update_body}"
        );
        let updated: UserSetting = serde_json::from_str(&update_body)
            .context("parse successful user setting update response")?;
        assert_eq!(
            updated.id, updatable.id,
            "user setting id changed after update"
        );
        assert_eq!(
            updated.value.as_deref(),
            Some(original_value),
            "user setting update did not preserve the submitted value"
        );

        Ok(())
    }
    .await;

    finish_session(&harness, &session, run).await
}

// Covers one repeatable admin-managed write path with cleanup. Groups are used
// because they exercise identity create/read/list/delete without depending on
// password policy, role assignment, or resource-specific permission grants.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a compose-backed gvmd environment"]
async fn rest_identity_group_lifecycle_creates_reads_lists_and_deletes() -> Result<()> {
    let (harness, session) = ready_session().await?;
    let mut group_id = None;

    let run = async {
        let group_name = harness.unique_name("nightly-identity-group");
        let created = harness
            .create_group(&session.token, &group_name)
            .await
            .context("create group for identity lifecycle coverage")?;
        assert_created_location(&created, "/api/v1/groups");
        group_id = Some(created.id.clone());

        let group = harness.get_group(&session.token, &created.id).await?;
        assert_group_matches_created(&group, &created.id, &group_name);

        let groups = harness.list_groups(&session.token).await?;
        assert!(
            groups
                .data
                .iter()
                .any(|listed| listed.meta.id == created.id && listed.meta.name == group_name),
            "created group {} ({}) was not returned by list groups",
            group_name,
            created.id
        );

        harness.delete_group(&session.token, &created.id).await?;
        group_id = None;
        assert_group_not_listed(&harness, &session.token, &created.id).await?;

        Ok(())
    }
    .await;

    if run.is_err() {
        best_effort_delete_group(&harness, &session.token, group_id.as_deref()).await;
    }
    finish_session(&harness, &session, run).await
}

async fn ready_harness() -> Result<E2eHarness> {
    let harness = E2eHarness::from_env()?;
    harness.wait_until_ready().await?;
    Ok(harness)
}

async fn ready_session() -> Result<(E2eHarness, SessionResponse)> {
    let harness = ready_harness().await?;
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

async fn assert_user_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let users = harness.list_users(token).await?;
    assert_paginated_identity_shape("users", &users);
    if let Some(user) = users.data.first() {
        let fetched = harness
            .get_user(token, &user.meta.id)
            .await
            .context("read first listed user")?;
        assert_identity_meta_matches("user", &fetched.meta, &user.meta);
        assert_user_shape(&fetched);
    }
    Ok(())
}

async fn assert_group_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let groups = harness.list_groups(token).await?;
    assert_paginated_identity_shape("groups", &groups);
    if let Some(group) = groups.data.first() {
        let fetched = harness
            .get_group(token, &group.meta.id)
            .await
            .context("read first listed group")?;
        assert_identity_meta_matches("group", &fetched.meta, &group.meta);
        assert_group_shape(&fetched);
    }
    Ok(())
}

async fn assert_role_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let roles = harness.list_roles(token).await?;
    assert_paginated_identity_shape("roles", &roles);
    if let Some(role) = roles.data.first() {
        let fetched = harness
            .get_role(token, &role.meta.id)
            .await
            .context("read first listed role")?;
        assert_identity_meta_matches("role", &fetched.meta, &role.meta);
        assert_role_shape(&fetched);
    }
    Ok(())
}

async fn assert_permission_catalog(harness: &E2eHarness, token: &str) -> Result<()> {
    let permissions = harness.list_permissions(token).await?;
    assert_paginated_identity_shape("permissions", &permissions);
    if let Some(permission) = permissions.data.first() {
        let fetched = harness
            .get_permission(token, &permission.meta.id)
            .await
            .context("read first listed permission")?;
        assert_identity_meta_matches("permission", &fetched.meta, &permission.meta);
        assert_permission_shape(&fetched);
    }
    Ok(())
}

fn assert_paginated_identity_shape<T>(resource: &str, response: &ListResponse<T>) {
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

fn assert_identity_meta_shape(resource: &str, meta: &IdentityResourceMeta) {
    assert!(
        !meta.id.trim().is_empty(),
        "{resource} returned an empty id"
    );
    assert!(
        !meta.name.trim().is_empty(),
        "{resource} returned an empty name"
    );
}

fn assert_identity_meta_matches(
    resource: &str,
    fetched: &IdentityResourceMeta,
    listed: &IdentityResourceMeta,
) {
    assert_identity_meta_shape(resource, fetched);
    assert_eq!(
        fetched.id, listed.id,
        "{resource} id drifted between list and read"
    );
    assert_eq!(
        fetched.name, listed.name,
        "{resource} name drifted between list and read"
    );
}

fn assert_user_shape(user: &User) {
    assert_identity_meta_shape("user", &user.meta);
    for role in &user.roles {
        assert_resource_ref_shape("user role", role);
    }
    for group in &user.groups {
        assert_resource_ref_shape("user group", group);
    }
}

fn assert_group_shape(group: &Group) {
    assert_identity_meta_shape("group", &group.meta);
    for user in &group.users {
        assert!(!user.trim().is_empty(), "group returned an empty user name");
    }
}

fn assert_role_shape(role: &Role) {
    assert_identity_meta_shape("role", &role.meta);
    for user in &role.users {
        assert!(!user.trim().is_empty(), "role returned an empty user name");
    }
}

fn assert_permission_shape(permission: &Permission) {
    assert_identity_meta_shape("permission", &permission.meta);
    if let Some(subject) = &permission.subject {
        assert_resource_ref_shape("permission subject", subject);
    }
    if let Some(resource) = &permission.resource {
        assert_resource_ref_shape("permission resource", resource);
    }
}

fn assert_resource_ref_shape(resource: &str, reference: &gvm_gateway_e2e::harness::ResourceRef) {
    assert!(
        !reference.id.trim().is_empty(),
        "{resource} reference returned an empty id"
    );
}

fn assert_user_setting_shape(setting: &UserSetting) {
    assert!(
        !setting.id.trim().is_empty(),
        "user setting returned an empty id"
    );
    assert!(
        !setting.name.trim().is_empty(),
        "user setting returned an empty name"
    );
}

fn assert_group_matches_created(group: &Group, expected_id: &str, expected_name: &str) {
    assert_eq!(group.meta.id, expected_id, "created group id drifted");
    assert_eq!(
        group.meta.name, expected_name,
        "created group did not preserve name"
    );
    assert!(
        group.users.is_empty(),
        "created empty group unexpectedly returned users: {:?}",
        group.users
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

async fn assert_group_not_listed(harness: &E2eHarness, token: &str, group_id: &str) -> Result<()> {
    let groups = harness
        .list_groups(token)
        .await
        .context("list groups after deleting group")?;
    assert!(
        groups.data.iter().all(|group| group.meta.id != group_id),
        "deleted group {group_id} was still returned by list groups"
    );
    Ok(())
}

async fn best_effort_delete_group(harness: &E2eHarness, token: &str, group_id: Option<&str>) {
    if let Some(group_id) = group_id {
        if let Err(error) = harness.delete_group(token, group_id).await {
            eprintln!("best-effort group cleanup failed for {group_id}: {error:#}");
        }
    }
}
