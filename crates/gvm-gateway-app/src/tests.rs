// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![cfg(test)]

use std::sync::Arc;

use async_trait::async_trait;
use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, GetReportOpts, ModifyTargetInput, ReadinessStatus,
    ReportQuery, ResultQuery, SessionLimits, SessionManager, SystemPort, TargetQuery,
};

use crate::{service::safe_session_id, test_support::*, GatewayService};

/// Health always reports `ok` because liveness is process-local.
#[test]
fn service_health_always_returns_ok() {
    let service = create_test_service();
    let health = service.health();
    assert_eq!(health.status, "ok");
}

/// Raw-token observability paths use the documented `session:<suffix>` format
/// without exposing the complete bearer token.
#[test]
fn safe_session_id_uses_documented_token_suffix() {
    let token = "gvm_sess_1234567890abcdef";

    let session_id = safe_session_id(token);

    assert_eq!(session_id, "session:90abcdef");
    assert!(!session_id.contains(token));
}

/// Ready forwards a healthy backend readiness response unchanged.
#[tokio::test]
async fn service_ready_returns_readiness() {
    let service = create_test_service();
    let ready = service.ready().await.unwrap();
    assert_eq!(ready.status, "ready");
    assert!(ready.reason.is_none());
}

/// Ready preserves a not-ready backend status and reason.
#[tokio::test]
async fn service_ready_returns_not_ready() {
    let service = GatewayService::new(
        Arc::new(MockSystemPort {
            ready: false,
            gmp_version: "22.7".to_string(),
        }),
        Arc::new(MockAlertPort),
        Arc::new(MockSchedulePort),
        Arc::new(MockCredentialPort),
        Arc::new(MockPortListPort),
        Arc::new(MockFeedPort),
        Arc::new(MockIdentityPort),
        Arc::new(MockTargetPort::default()),
        Arc::new(MockTaskPort),
        Arc::new(MockAuthPort::default()),
        Arc::new(MockReportPort),
        Arc::new(MockResultPort),
        Arc::new(MockScanConfigPort),
        Arc::new(MockScannerPort),
        Arc::new(MockSupportingResourcePort),
        Arc::new(SessionManager::default()),
    );
    let ready = service.ready().await.unwrap();
    assert_eq!(ready.status, "notReady");
    assert!(ready.reason.is_some());
}

/// Version includes both the crate version and the backend GMP version.
#[tokio::test]
async fn service_version_returns_api_and_gmp_version() {
    let service = create_test_service();
    let version = service.version().await.unwrap();
    assert_eq!(version.gmp_version, "22.7");
    assert!(!version.api_version.is_empty());
}

#[derive(Clone)]
struct FailingVersionSystemPort;

#[async_trait]
impl SystemPort for FailingVersionSystemPort {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        Ok(ReadinessStatus {
            status: "ready",
            reason: None,
        })
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "version probe failed".to_string(),
        ))
    }
}

/// Session creation must use the version negotiated by the authenticated
/// backend connection instead of opening a second connection for a post-auth
/// version probe that can fail and orphan the newly created session.
#[tokio::test]
async fn service_create_session_uses_authenticated_version_without_extra_probe() {
    let sessions = Arc::new(SessionManager::with_limits(
        300,
        SessionLimits {
            max_global: Some(1),
            max_per_user: Some(1),
        },
    ));
    let auth = Arc::new(MockAuthPort {
        gmp_version: "22.9".to_string(),
        ..Default::default()
    });
    let disconnected = Arc::clone(&auth.disconnected);
    let service = GatewayService::new(
        Arc::new(FailingVersionSystemPort),
        Arc::new(MockAlertPort),
        Arc::new(MockSchedulePort),
        Arc::new(MockCredentialPort),
        Arc::new(MockPortListPort),
        Arc::new(MockFeedPort),
        Arc::new(MockIdentityPort),
        Arc::new(MockTargetPort::default()),
        Arc::new(MockTaskPort),
        auth,
        Arc::new(MockReportPort),
        Arc::new(MockResultPort),
        Arc::new(MockScanConfigPort),
        Arc::new(MockScannerPort),
        Arc::new(MockSupportingResourcePort),
        Arc::clone(&sessions),
    );

    let created = service.create_session("admin", "secret").await.unwrap();

    assert_eq!(created.gmp_version, "22.9");
    assert!(service.get_session(&created.token).is_ok());
    assert!(disconnected.lock().unwrap().is_empty());
}

/// Target listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_targets_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_targets("invalid-token", TargetQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_targets_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_targets(&session.token, TargetQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Target creation rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_create_target_requires_valid_session() {
    let service = create_test_service();
    let input = CreateTargetInput {
        name: "test".to_string(),
        comment: None,
        hosts: vec!["127.0.0.1".to_string()],
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
    let result = service.create_target("invalid-token", input).await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_target_requires_valid_session() {
    let service = create_test_service();
    let result = service.get_target("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target modification rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_modify_target_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .modify_target("invalid-token", "some-id", ModifyTargetInput::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Target deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_target_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .delete_target("invalid-token", "some-id", false)
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Expired sessions are rejected consistently by target operations.
#[tokio::test]
async fn service_operations_fail_with_expired_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    service.session_manager().expire(&session.token).unwrap();

    let result = service
        .list_targets(&session.token, TargetQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
}

/// Report listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_reports_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_reports("invalid-token", ReportQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Report listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_reports_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_reports(&session.token, ReportQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Report fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_report_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .get_report("invalid-token", "some-id", GetReportOpts::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Report export rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_export_report_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .export_report("invalid-token", "some-report-id", "some-report-format-id")
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Report deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_report_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .delete_report("invalid-token", "some-id", false)
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Result listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_results_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_results("invalid-token", ResultQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Result listing succeeds after a valid session is created.
#[tokio::test]
async fn service_list_results_with_valid_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    let result = service
        .list_results(&session.token, ResultQuery::default())
        .await;
    assert!(result.is_ok());
}

/// Result fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_result_requires_valid_session() {
    let service = create_test_service();
    let result = service.get_result("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}

/// Expired sessions are rejected consistently by report operations.
#[tokio::test]
async fn service_report_operations_fail_with_expired_session() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();
    service.session_manager().expire(&session.token).unwrap();

    let result = service
        .list_reports(&session.token, ReportQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
}

/// Audit logs record auth failures without leaking credentials or raw session tokens.
#[tokio::test]
async fn audit_logs_redact_sensitive_fields_and_record_session_creation_failure() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let service = GatewayService::new(
                Arc::new(MockSystemPort {
                    ready: true,
                    gmp_version: "22.7".to_string(),
                }),
                Arc::new(MockAlertPort),
                Arc::new(MockSchedulePort),
                Arc::new(MockCredentialPort),
                Arc::new(MockPortListPort),
                Arc::new(MockFeedPort),
                Arc::new(MockIdentityPort),
                Arc::new(MockTargetPort::default()),
                Arc::new(MockTaskPort),
                Arc::new(MockAuthPort {
                    should_fail: true,
                    ..Default::default()
                }),
                Arc::new(MockReportPort),
                Arc::new(MockResultPort),
                Arc::new(MockScanConfigPort),
                Arc::new(MockScannerPort),
                Arc::new(MockSupportingResourcePort),
                Arc::new(SessionManager::default()),
            );

            let _ = service
                .create_session("admin", "super-secret-password")
                .await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"session.create\""));
    assert!(output.contains("audit_outcome=\"failure\""));
    assert!(output.contains("gvmd_username=admin"));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains("super-secret-password"));
    assert!(!output.contains("gvm_sess_"));
}

/// Audit logs tie command failures back to session expiry without exposing raw tokens.
#[tokio::test]
async fn audit_logs_command_execution_and_session_expiry_events() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let service = create_test_service();
            let session = service.create_session("admin", "secret").await.unwrap();
            service.session_manager().expire(&session.token).unwrap();

            let _ = service
                .list_targets(&session.token, TargetQuery::default())
                .await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_event=\"session.expired\""));
    assert!(output.contains("error_category=\"session_expired\""));
}

/// Mutating resource workflows emit audit events with safe session context only.
#[tokio::test]
async fn audit_logs_target_mutation_without_raw_session_token() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    let session_token = capture
        .run(async {
            let service = create_test_service();
            let session = service
                .create_session("admin", "super-secret-password")
                .await
                .unwrap();

            let result = service
                .create_target(
                    &session.token,
                    CreateTargetInput {
                        name: "target-a".to_string(),
                        comment: None,
                        hosts: vec!["192.0.2.10".to_string()],
                        exclude_hosts: vec![],
                        alive_test: None,
                        port_list_id: None,
                        reverse_lookup_only: None,
                        reverse_lookup_unify: None,
                        ssh_credential_id: None,
                        smb_credential_id: None,
                        esxi_credential_id: None,
                        snmp_credential_id: None,
                    },
                )
                .await;
            assert!(result.is_ok());

            session.token
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_outcome=\"success\""));
    assert!(output.contains("resource=\"target\""));
    assert!(output.contains("action=\"create\""));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains(&session_token));
    assert!(!output.contains("super-secret-password"));
}

/// Report export audit logs use a dedicated action separate from ordinary reads.
#[tokio::test]
async fn audit_logs_report_export_with_export_action() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    let session_token = capture
        .run(async {
            let service = create_test_service();
            let session = service.create_session("admin", "secret").await.unwrap();

            let _ = service
                .export_report(
                    &session.token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    "123e4567-e89b-12d3-a456-426614174000",
                )
                .await;

            session.token
        })
        .await;

    let output = capture.output();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("resource=\"report_export\""));
    assert!(output.contains("action=\"export\""));
    assert!(!output.contains("action=\"read\""));
    assert!(!output.contains(&session_token));
}

/// Spans are emitted for both session lifecycle and resource command execution.
#[tokio::test]
async fn spans_are_emitted_for_session_and_command_lifecycle() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    capture
        .run(async {
            let service = GatewayService::new(
                Arc::new(MockSystemPort {
                    ready: true,
                    gmp_version: "22.7".to_string(),
                }),
                Arc::new(MockAlertPort),
                Arc::new(MockSchedulePort),
                Arc::new(MockCredentialPort),
                Arc::new(MockPortListPort),
                Arc::new(MockFeedPort),
                Arc::new(MockIdentityPort),
                Arc::new(MockTargetPort { should_fail: true }),
                Arc::new(MockTaskPort),
                Arc::new(MockAuthPort::default()),
                Arc::new(MockReportPort),
                Arc::new(MockResultPort),
                Arc::new(MockScanConfigPort),
                Arc::new(MockScannerPort),
                Arc::new(MockSupportingResourcePort),
                Arc::new(SessionManager::default()),
            );

            let session = service.create_session("admin", "secret").await.unwrap();
            let _ = service.get_target(&session.token, "resource-123").await;
            let _ = service.delete_session(&session.token).await;
        })
        .await;

    let output = capture.output();
    assert!(output.contains("session.create"));
    assert!(output.contains("command.execution"));
    assert!(output.contains("targets.get"));
    assert!(output.contains("session.teardown"));
}
