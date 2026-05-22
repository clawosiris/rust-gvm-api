// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![cfg(test)]

use std::sync::Arc;

use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, GetReportOpts, ModifyTargetInput, ReportQuery, ResultQuery,
    SessionManager, TargetQuery,
};

use crate::{test_support::*, GatewayService};

/// Health always reports `ok` because liveness is process-local.
#[test]
fn service_health_always_returns_ok() {
    let service = create_test_service();
    let health = service.health();
    assert_eq!(health.status, "ok");
}

/// Ready forwards a healthy backend readiness response unchanged.
#[test]
fn service_ready_returns_readiness() {
    let service = create_test_service();
    let ready = service.ready().unwrap();
    assert_eq!(ready.status, "ready");
    assert!(ready.reason.is_none());
}

/// Ready preserves a not-ready backend status and reason.
#[test]
fn service_ready_returns_not_ready() {
    let service = GatewayService::new(
        Arc::new(MockSystemPort {
            ready: false,
            gmp_version: "22.7".to_string(),
        }),
        Arc::new(MockTargetPort::default()),
        Arc::new(MockTaskPort),
        Arc::new(MockAuthPort::default()),
        Arc::new(MockReportPort),
        Arc::new(MockResultPort),
        Arc::new(MockScanConfigPort),
        Arc::new(MockScannerPort),
        Arc::new(SessionManager::default()),
    );
    let ready = service.ready().unwrap();
    assert_eq!(ready.status, "notReady");
    assert!(ready.reason.is_some());
}

/// Version includes both the crate version and the backend GMP version.
#[test]
fn service_version_returns_api_and_gmp_version() {
    let service = create_test_service();
    let version = service.version().unwrap();
    assert_eq!(version.gmp_version, "22.7");
    assert!(!version.api_version.is_empty());
}

/// Target listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_targets_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_targets("invalid-token", TargetQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
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
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Target fetch rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_get_target_requires_valid_session() {
    let service = create_test_service();
    let result = service.get_target("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Target modification rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_modify_target_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .modify_target("invalid-token", "some-id", ModifyTargetInput::default())
        .await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Target deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_target_requires_valid_session() {
    let service = create_test_service();
    let result = service.delete_target("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
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
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Report listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_reports_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_reports("invalid-token", ReportQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
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
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Report deletion rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_delete_report_requires_valid_session() {
    let service = create_test_service();
    let result = service.delete_report("invalid-token", "some-id").await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Result listing rejects unknown session tokens before hitting the port.
#[tokio::test]
async fn service_list_results_requires_valid_session() {
    let service = create_test_service();
    let result = service
        .list_results("invalid-token", ResultQuery::default())
        .await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
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
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
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
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// Audit logs record auth failures without leaking credentials or raw session tokens.
#[tokio::test]
async fn audit_logs_redact_sensitive_fields_and_record_session_creation_failure() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
    let service = GatewayService::new(
        Arc::new(MockSystemPort {
            ready: true,
            gmp_version: "22.7".to_string(),
        }),
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
        Arc::new(SessionManager::default()),
    );

    let _ = service
        .create_session("admin", "super-secret-password")
        .await;

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
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
    let logs = capture_tracing();
    let service = create_test_service();
    let session = service.create_session("admin", "secret").await.unwrap();
    service.session_manager().expire(&session.token).unwrap();

    let _ = service
        .list_targets(&session.token, TargetQuery::default())
        .await;

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_event=\"session.expired\""));
    assert!(output.contains("error_category=\"session_expired\""));
}

/// Mutating resource workflows emit audit events with safe session context only.
#[tokio::test]
async fn audit_logs_target_mutation_without_raw_session_token() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
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

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("audit_event=\"command.execution\""));
    assert!(output.contains("audit_outcome=\"start\""));
    assert!(output.contains("audit_outcome=\"success\""));
    assert!(output.contains("resource=\"target\""));
    assert!(output.contains("action=\"create\""));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains(&session.token));
    assert!(!output.contains("super-secret-password"));
}

/// Spans are emitted for both session lifecycle and resource command execution.
#[tokio::test]
async fn spans_are_emitted_for_session_and_command_lifecycle() {
    let _trace_lock = lock_tracing().await;
    let logs = capture_tracing();
    let service = GatewayService::new(
        Arc::new(MockSystemPort {
            ready: true,
            gmp_version: "22.7".to_string(),
        }),
        Arc::new(MockTargetPort { should_fail: true }),
        Arc::new(MockTaskPort),
        Arc::new(MockAuthPort::default()),
        Arc::new(MockReportPort),
        Arc::new(MockResultPort),
        Arc::new(MockScanConfigPort),
        Arc::new(MockScannerPort),
        Arc::new(SessionManager::default()),
    );

    let session = service.create_session("admin", "secret").await.unwrap();
    let _ = service.get_target(&session.token, "resource-123").await;
    let _ = service.delete_session(&session.token).await;

    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(output.contains("session.create"));
    assert!(output.contains("command.execution"));
    assert!(output.contains("targets.get"));
    assert!(output.contains("session.teardown"));
}
