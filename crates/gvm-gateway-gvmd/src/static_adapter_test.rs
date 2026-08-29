// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

#[tokio::test]
async fn static_adapter_ready_returns_ready_status() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let status = adapter.readiness().await.unwrap();
    assert_eq!(status.status, "ready");
    assert!(status.reason.is_none());
}

#[tokio::test]
async fn static_adapter_ready_returns_gmp_version() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let version = adapter.gmp_version().await.unwrap();
    assert_eq!(version, "22.7");
}

#[tokio::test]
async fn static_adapter_authenticate_session_returns_gmp_version() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let version = adapter
        .authenticate_session("token", "admin", "secret")
        .await
        .unwrap();
    assert_eq!(version, "22.7");
}

#[tokio::test]
async fn static_adapter_not_ready_returns_not_ready_status() {
    let adapter = StaticGvmdAdapter::not_ready("gvmd offline", "22.7");
    let status = adapter.readiness().await.unwrap();
    assert_eq!(status.status, "notReady");
    assert_eq!(status.reason.as_deref(), Some("gvmd offline"));
}

#[tokio::test]
async fn static_adapter_not_ready_gmp_version_fails() {
    let adapter = StaticGvmdAdapter::not_ready("gvmd offline", "22.7");
    let result = adapter.gmp_version().await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

#[tokio::test]
async fn static_adapter_list_targets_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter.list_targets("token", &TargetQuery::default()).await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

#[tokio::test]
async fn static_adapter_create_target_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let input = CreateTargetInput {
        name: "test".to_string(),
        comment: None,
        hosts: vec![],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    };
    let result = adapter.create_target("token", input).await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

#[tokio::test]
async fn static_adapter_get_target_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter.get_target("token", "id").await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

#[tokio::test]
async fn static_adapter_modify_target_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter
        .modify_target("token", "id", ModifyTargetInput::default())
        .await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

#[tokio::test]
async fn static_adapter_delete_target_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter.delete_target("token", "id", false).await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

/// Focused SecInfo list reads must stay unavailable on the static adapter so
/// router-only tests do not accidentally pretend to serve live catalog data.
#[tokio::test]
async fn static_adapter_list_cves_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter
        .list_cves("token", &SupportingResourceQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}

/// SecInfo item reads remain a backend operation and should therefore fail
/// uniformly on the static adapter for non-UUID identifiers as well.
#[tokio::test]
async fn static_adapter_get_dfn_cert_advisory_unsupported() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let result = adapter.get_dfn_cert_advisory("token", "DFN-2026-001").await;
    assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
}
