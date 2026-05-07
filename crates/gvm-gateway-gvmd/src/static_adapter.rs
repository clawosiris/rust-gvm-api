// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Static (stub) adapter that reports system readiness but rejects all
//! operational queries. Used as a fallback when gvmd is unavailable.

use async_trait::async_trait;
use gvm_gateway_domain::{
    AuthPort, CreateScanConfigInput, CreateTargetInput, CreateTaskInput, GatewayError,
    GetReportOpts, ModifyScanConfigInput, ModifyTargetInput, ModifyTaskInput, ReadinessStatus,
    Report, ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort, ResultQuery, ScanConfig,
    ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort,
    ScannerQuery, SystemPort, Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction,
    TaskPage, TaskPort, TaskQuery,
};

/// Static adapter for system readiness and version information.
#[derive(Clone, Debug)]
pub struct StaticGvmdAdapter {
    ready: bool,
    reason: Option<String>,
    gmp_version: String,
}

impl StaticGvmdAdapter {
    /// Creates a ready adapter with the provided GMP version.
    pub fn ready(gmp_version: impl Into<String>) -> Self {
        Self {
            ready: true,
            reason: None,
            gmp_version: gmp_version.into(),
        }
    }

    /// Creates an unready adapter with a reason and GMP version.
    pub fn not_ready(reason: impl Into<String>, gmp_version: impl Into<String>) -> Self {
        Self {
            ready: false,
            reason: Some(reason.into()),
            gmp_version: gmp_version.into(),
        }
    }
}

impl SystemPort for StaticGvmdAdapter {
    fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        if self.ready {
            Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            })
        } else {
            Ok(ReadinessStatus {
                status: "notReady",
                reason: self.reason.clone(),
            })
        }
    }

    fn gmp_version(&self) -> Result<String, GatewayError> {
        if self.ready {
            Ok(self.gmp_version.clone())
        } else {
            Err(GatewayError::BackendUnavailable(
                self.reason
                    .clone()
                    .unwrap_or_else(|| "gvmd unavailable".to_string()),
            ))
        }
    }
}

#[async_trait]
impl TargetPort for StaticGvmdAdapter {
    async fn list_targets(&self, _: &str, _: &TargetQuery) -> Result<TargetPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn create_target(&self, _: &str, _: CreateTargetInput) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn get_target(&self, _: &str, _: &str) -> Result<Target, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn modify_target(
        &self,
        _: &str,
        _: &str,
        _: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn delete_target(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }
}

#[async_trait]
impl TaskPort for StaticGvmdAdapter {
    async fn list_tasks(&self, _: &str, _: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn get_task(&self, _: &str, _: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn modify_task(
        &self,
        _: &str,
        _: &str,
        _: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn delete_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support tasks".to_string(),
        ))
    }
}

#[async_trait]
impl ReportPort for StaticGvmdAdapter {
    async fn list_reports(&self, _: &str, _: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report(
        &self,
        _: &str,
        _: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn delete_report(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        _: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support reports".to_string(),
        ))
    }
}

#[async_trait]
impl ResultPort for StaticGvmdAdapter {
    async fn list_results(&self, _: &str, _: &ResultQuery) -> Result<ResultPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support results".to_string(),
        ))
    }

    async fn get_result(&self, _: &str, _: &str) -> Result<ScanResult, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support results".to_string(),
        ))
    }
}

#[async_trait]
impl ScanConfigPort for StaticGvmdAdapter {
    async fn list_scan_configs(
        &self,
        _: &str,
        _: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn create_scan_config(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn get_scan_config(&self, _: &str, _: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn modify_scan_config(
        &self,
        _: &str,
        _: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }

    async fn delete_scan_config(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scan configs".to_string(),
        ))
    }
}

#[async_trait]
impl ScannerPort for StaticGvmdAdapter {
    async fn list_scanners(&self, _: &str, _: &ScannerQuery) -> Result<ScannerPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scanners".to_string(),
        ))
    }

    async fn get_scanner(&self, _: &str, _: &str) -> Result<Scanner, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support scanners".to_string(),
        ))
    }
}

#[async_trait]
impl AuthPort for StaticGvmdAdapter {
    async fn authenticate_session(
        &self,
        _session_token: &str,
        _username: &str,
        _password: &str,
    ) -> Result<(), GatewayError> {
        if self.ready {
            Ok(())
        } else {
            Err(GatewayError::BackendUnavailable(
                "static adapter not ready".to_string(),
            ))
        }
    }

    async fn disconnect_session(&self, _session_token: &str) -> Result<(), GatewayError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_adapter_ready_returns_ready_status() {
        let adapter = StaticGvmdAdapter::ready("22.7");
        let status = adapter.readiness().unwrap();
        assert_eq!(status.status, "ready");
        assert!(status.reason.is_none());
    }

    #[test]
    fn static_adapter_ready_returns_gmp_version() {
        let adapter = StaticGvmdAdapter::ready("22.7");
        let version = adapter.gmp_version().unwrap();
        assert_eq!(version, "22.7");
    }

    #[test]
    fn static_adapter_not_ready_returns_not_ready_status() {
        let adapter = StaticGvmdAdapter::not_ready("gvmd offline", "22.7");
        let status = adapter.readiness().unwrap();
        assert_eq!(status.status, "notReady");
        assert_eq!(status.reason.as_deref(), Some("gvmd offline"));
    }

    #[test]
    fn static_adapter_not_ready_gmp_version_fails() {
        let adapter = StaticGvmdAdapter::not_ready("gvmd offline", "22.7");
        let result = adapter.gmp_version();
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
        let result = adapter.delete_target("token", "id").await;
        assert!(matches!(result, Err(GatewayError::BackendUnavailable(_))));
    }
}
