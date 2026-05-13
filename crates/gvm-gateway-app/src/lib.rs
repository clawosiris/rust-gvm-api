// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

mod session;

pub use session::SessionReaper;

use std::sync::Arc;

use gvm_gateway_domain::{
    AuthPort, CreateScanConfigInput, CreateTargetInput, CreateTaskInput, GatewayError,
    GetReportOpts, HealthStatus, ModifyScanConfigInput, ModifyTargetInput, ModifyTaskInput,
    ReadinessStatus, Report, ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort,
    ResultQuery, ScanConfig, ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner,
    ScannerPage, ScannerPort, ScannerQuery, SessionManager, SystemPort, Target, TargetPage,
    TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery, VersionInfo,
};
use tracing::{field, info_span, Instrument};

pub(crate) const AUDIT_TARGET: &str = "gvm_gateway_app::audit";

/// Application services exposed to adapters.
///
/// Ports are held as trait objects so that adding a new resource does not
/// require touching unrelated handler signatures.
pub struct GatewayService {
    system: Arc<dyn SystemPort>,
    targets: Arc<dyn TargetPort>,
    tasks: Arc<dyn TaskPort>,
    auth: Arc<dyn AuthPort>,
    reports: Arc<dyn ReportPort>,
    results: Arc<dyn ResultPort>,
    scan_configs: Arc<dyn ScanConfigPort>,
    scanners: Arc<dyn ScannerPort>,
    sessions: Arc<SessionManager>,
}

impl GatewayService {
    /// Creates a new service backed by the provided ports and session manager.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system: Arc<dyn SystemPort>,
        targets: Arc<dyn TargetPort>,
        tasks: Arc<dyn TaskPort>,
        auth: Arc<dyn AuthPort>,
        reports: Arc<dyn ReportPort>,
        results: Arc<dyn ResultPort>,
        scan_configs: Arc<dyn ScanConfigPort>,
        scanners: Arc<dyn ScannerPort>,
        sessions: Arc<SessionManager>,
    ) -> Self {
        Self {
            system,
            targets,
            tasks,
            auth,
            reports,
            results,
            scan_configs,
            scanners,
            sessions,
        }
    }

    // ------------------------------------------------------------------
    // Health & system
    // ------------------------------------------------------------------

    /// Returns liveness information.
    pub fn health(&self) -> HealthStatus {
        HealthStatus { status: "ok" }
    }

    /// Returns readiness information.
    pub fn ready(&self) -> Result<ReadinessStatus, GatewayError> {
        self.system.readiness()
    }

    /// Returns version information.
    pub fn version(&self) -> Result<VersionInfo, GatewayError> {
        let gmp_version = self.system.gmp_version()?;
        Ok(VersionInfo {
            api_version: env!("CARGO_PKG_VERSION").to_string(),
            gmp_version,
        })
    }

    // ------------------------------------------------------------------
    // Targets
    // ------------------------------------------------------------------

    /// Lists targets for an authenticated session.
    pub async fn list_targets(
        &self,
        session_token: &str,
        query: TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        self.execute_with_resource(
            "targets.list",
            session_token,
            "list",
            "target",
            None,
            |session| async move { self.targets.list_targets(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new target for an authenticated session.
    pub async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "targets.create",
            session_token,
            "create",
            "target",
            None,
            |session| async move { self.targets.create_target(&session.token, input).await },
        )
        .await
    }

    /// Fetches a target for an authenticated session.
    pub async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.get",
            session_token,
            "read",
            "target",
            Some(id),
            |session| async move { self.targets.get_target(&session.token, id).await },
        )
        .await
    }

    /// Modifies a target for an authenticated session.
    pub async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.modify",
            session_token,
            "modify",
            "target",
            Some(id),
            |session| async move { self.targets.modify_target(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a target for an authenticated session.
    pub async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "targets.delete",
            session_token,
            "delete",
            "target",
            Some(id),
            |session| async move { self.targets.delete_target(&session.token, id).await },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Tasks
    // ------------------------------------------------------------------

    /// Lists tasks for an authenticated session.
    pub async fn list_tasks(
        &self,
        session_token: &str,
        query: TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
        self.execute_with_resource(
            "tasks.list",
            session_token,
            "list",
            "task",
            None,
            |session| async move { self.tasks.list_tasks(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new task for an authenticated session.
    pub async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tasks.create",
            session_token,
            "create",
            "task",
            None,
            |session| async move { self.tasks.create_task(&session.token, input).await },
        )
        .await
    }

    /// Fetches a task for an authenticated session.
    pub async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.get",
            session_token,
            "read",
            "task",
            Some(id),
            |session| async move { self.tasks.get_task(&session.token, id).await },
        )
        .await
    }

    /// Modifies a task for an authenticated session.
    pub async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        self.execute_with_resource(
            "tasks.modify",
            session_token,
            "modify",
            "task",
            Some(id),
            |session| async move { self.tasks.modify_task(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a task for an authenticated session.
    pub async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.delete",
            session_token,
            "delete",
            "task",
            Some(id),
            |session| async move { self.tasks.delete_task(&session.token, id).await },
        )
        .await
    }

    /// Starts a task for an authenticated session.
    pub async fn start_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.start",
            session_token,
            "start",
            "task",
            Some(id),
            |session| async move { self.tasks.start_task(&session.token, id).await },
        )
        .await
    }

    /// Stops a running task for an authenticated session.
    pub async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tasks.stop",
            session_token,
            "stop",
            "task",
            Some(id),
            |session| async move { self.tasks.stop_task(&session.token, id).await },
        )
        .await
    }

    /// Resumes a stopped task for an authenticated session.
    pub async fn resume_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        self.execute_with_resource(
            "tasks.resume",
            session_token,
            "resume",
            "task",
            Some(id),
            |session| async move { self.tasks.resume_task(&session.token, id).await },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Reports
    // ------------------------------------------------------------------

    /// Lists reports for an authenticated session.
    pub async fn list_reports(
        &self,
        session_token: &str,
        query: ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        self.execute_with_resource(
            "reports.list",
            session_token,
            "list",
            "report",
            None,
            |session| async move { self.reports.list_reports(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a report for an authenticated session.
    pub async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: GetReportOpts,
    ) -> Result<Report, GatewayError> {
        self.execute_with_resource(
            "reports.get",
            session_token,
            "read",
            "report",
            Some(id),
            |session| async move { self.reports.get_report(&session.token, id, &opts).await },
        )
        .await
    }

    /// Deletes a report for an authenticated session.
    pub async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "reports.delete",
            session_token,
            "delete",
            "report",
            Some(id),
            |session| async move { self.reports.delete_report(&session.token, id).await },
        )
        .await
    }

    /// Lists results for a specific report.
    pub async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "reports.results.list",
            session_token,
            "list",
            "report_result",
            Some(report_id),
            |session| async move {
                self.reports
                    .get_report_results(&session.token, report_id, &query)
                    .await
            },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Results
    // ------------------------------------------------------------------

    /// Lists results for an authenticated session.
    pub async fn list_results(
        &self,
        session_token: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "results.list",
            session_token,
            "list",
            "result",
            None,
            |session| async move { self.results.list_results(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a result for an authenticated session.
    pub async fn get_result(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanResult, GatewayError> {
        self.execute_with_resource(
            "results.get",
            session_token,
            "read",
            "result",
            Some(id),
            |session| async move { self.results.get_result(&session.token, id).await },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Scan Configs
    // ------------------------------------------------------------------

    /// Lists scan configs for an authenticated session.
    pub async fn list_scan_configs(
        &self,
        session_token: &str,
        query: ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        self.execute_with_resource(
            "scan_configs.list",
            session_token,
            "list",
            "scan_config",
            None,
            |session| async move {
                self.scan_configs
                    .list_scan_configs(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Creates a new scan config for an authenticated session.
    pub async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "scan_configs.create",
            session_token,
            "create",
            "scan_config",
            None,
            |session| async move {
                self.scan_configs
                    .create_scan_config(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Fetches a scan config for an authenticated session.
    pub async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "scan_configs.get",
            session_token,
            "read",
            "scan_config",
            Some(id),
            |session| async move { self.scan_configs.get_scan_config(&session.token, id).await },
        )
        .await
    }

    /// Modifies a scan config for an authenticated session.
    pub async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        self.execute_with_resource(
            "scan_configs.modify",
            session_token,
            "modify",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .modify_scan_config(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a scan config for an authenticated session.
    pub async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "scan_configs.delete",
            session_token,
            "delete",
            "scan_config",
            Some(id),
            |session| async move {
                self.scan_configs
                    .delete_scan_config(&session.token, id)
                    .await
            },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Scanners
    // ------------------------------------------------------------------

    /// Lists scanners for an authenticated session.
    pub async fn list_scanners(
        &self,
        session_token: &str,
        query: ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        self.execute_with_resource(
            "scanners.list",
            session_token,
            "list",
            "scanner",
            None,
            |session| async move { self.scanners.list_scanners(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a scanner for an authenticated session.
    pub async fn get_scanner(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Scanner, GatewayError> {
        self.execute_with_resource(
            "scanners.get",
            session_token,
            "read",
            "scanner",
            Some(id),
            |session| async move { self.scanners.get_scanner(&session.token, id).await },
        )
        .await
    }
}

impl GatewayService {
    pub(crate) fn get_username_for_audit(&self, session_token: &str) -> Option<String> {
        self.sessions
            .get(session_token)
            .ok()
            .flatten()
            .map(|session| session.user)
    }

    pub(crate) fn touch_session_with_audit(
        &self,
        session_token: &str,
    ) -> Result<gvm_gateway_domain::Session, GatewayError> {
        match self.sessions.touch(session_token) {
            Ok(session) => Ok(session),
            Err(err) => {
                let reason = match &err {
                    GatewayError::Unauthorized(message) if message.contains("expired") => {
                        "session.expired"
                    }
                    GatewayError::Unauthorized(message) if message.contains("missing") => {
                        "session.invalidated"
                    }
                    _ => "session.lookup_failed",
                };
                emit_audit_event(
                    reason,
                    "failure",
                    self.get_username_for_audit(session_token)
                        .as_deref()
                        .unwrap_or("unknown"),
                    Some(session_token),
                    None,
                    None,
                    Some(&err),
                );
                Err(err)
            }
        }
    }

    async fn execute_with_resource<F, Fut, T>(
        &self,
        span_name: &'static str,
        session_token: &str,
        action: &'static str,
        resource: &'static str,
        resource_id: Option<&str>,
        operation: F,
    ) -> Result<T, GatewayError>
    where
        F: FnOnce(gvm_gateway_domain::Session) -> Fut,
        Fut: std::future::Future<Output = Result<T, GatewayError>>,
    {
        let user = self.get_username_for_audit(session_token);
        let span = execution_span(span_name, session_token, user.as_deref(), action, resource);
        span.record("resource_id", resource_id.unwrap_or(""));

        async move {
            emit_audit_event(
                "command.execution",
                "start",
                user.as_deref().unwrap_or("unknown"),
                Some(session_token),
                Some(resource),
                Some(action),
                None,
            );

            let session = self.touch_session_with_audit(session_token)?;
            let username = session.user.clone();

            match operation(session).await {
                Ok(result) => {
                    emit_audit_event(
                        "command.execution",
                        "success",
                        &username,
                        Some(session_token),
                        Some(resource),
                        Some(action),
                        None,
                    );
                    Ok(result)
                }
                Err(err) => {
                    emit_audit_event(
                        "command.execution",
                        "failure",
                        &username,
                        Some(session_token),
                        Some(resource),
                        Some(action),
                        Some(&err),
                    );
                    Err(err)
                }
            }
        }
        .instrument(span)
        .await
    }
}

pub(crate) fn execution_span(
    name: &'static str,
    session_token: &str,
    username: Option<&str>,
    action: &'static str,
    resource: &'static str,
) -> tracing::Span {
    info_span!(
        "command.execution",
        otel_name = name,
        gvmd_username = %username.unwrap_or("unknown"),
        session_id = %safe_session_id(session_token),
        audit_action = action,
        audit_resource = resource,
        resource_id = field::Empty
    )
}

pub(crate) fn safe_session_id(token: &str) -> String {
    let suffix: String = token
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("session:{suffix}")
}

fn error_category(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::BackendUnavailable(_) => "backend_unavailable",
        GatewayError::NotFound(_) => "not_found",
        GatewayError::InvalidInput(_) => "invalid_input",
        GatewayError::Unauthorized(message) if message.contains("expired") => "session_expired",
        GatewayError::Unauthorized(message) if message.contains("missing") => "session_invalidated",
        GatewayError::Unauthorized(_) => "unauthorized",
        GatewayError::Conflict(_) => "conflict",
        GatewayError::GatewayTimeout(_) => "gateway_timeout",
    }
}

pub(crate) fn emit_audit_event(
    event: &str,
    outcome: &str,
    username: &str,
    session_token: Option<&str>,
    resource: Option<&str>,
    action: Option<&str>,
    error: Option<&GatewayError>,
) {
    tracing::info!(
        target: AUDIT_TARGET,
        audit_event = event,
        audit_outcome = outcome,
        gvmd_username = username,
        session_id = session_token
            .map(safe_session_id)
            .unwrap_or_else(|| "session:unknown".to_string()),
        resource = resource.unwrap_or("session"),
        action = action.unwrap_or("none"),
        error_category = error.map(error_category).unwrap_or("none"),
        error = error.map(|err| format!("{err:?}")).unwrap_or_default(),
        "audit_event"
    );
}

impl Clone for GatewayService {
    fn clone(&self) -> Self {
        Self {
            system: Arc::clone(&self.system),
            targets: Arc::clone(&self.targets),
            tasks: Arc::clone(&self.tasks),
            auth: Arc::clone(&self.auth),
            reports: Arc::clone(&self.reports),
            results: Arc::clone(&self.results),
            scan_configs: Arc::clone(&self.scan_configs),
            scanners: Arc::clone(&self.scanners),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

// ============================================================================
// Shared test support (mocks + service factory)
// ============================================================================

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use async_trait::async_trait;
    use std::{
        io,
        sync::{Mutex, OnceLock},
    };
    use tracing_subscriber::{
        fmt::{self, format::FmtSpan},
        prelude::*,
        EnvFilter,
    };

    // Mock system port for testing
    #[derive(Clone)]
    pub(crate) struct MockSystemPort {
        pub(crate) ready: bool,
        pub(crate) gmp_version: String,
    }

    impl SystemPort for MockSystemPort {
        fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
            if self.ready {
                Ok(ReadinessStatus {
                    status: "ready",
                    reason: None,
                })
            } else {
                Ok(ReadinessStatus {
                    status: "notReady",
                    reason: Some("mock not ready".to_string()),
                })
            }
        }

        fn gmp_version(&self) -> Result<String, GatewayError> {
            Ok(self.gmp_version.clone())
        }
    }

    // Mock target port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockTargetPort {
        pub(crate) should_fail: bool,
    }

    #[async_trait]
    impl TargetPort for MockTargetPort {
        async fn list_targets(
            &self,
            _session_token: &str,
            query: &TargetQuery,
        ) -> Result<TargetPage, GatewayError> {
            if self.should_fail {
                return Err(GatewayError::BackendUnavailable("mock error".to_string()));
            }
            Ok(TargetPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn create_target(
            &self,
            _session_token: &str,
            _input: CreateTargetInput,
        ) -> Result<String, GatewayError> {
            if self.should_fail {
                return Err(GatewayError::BackendUnavailable("mock error".to_string()));
            }
            Ok("mock-target-id".to_string())
        }

        async fn get_target(&self, _session_token: &str, id: &str) -> Result<Target, GatewayError> {
            if self.should_fail {
                return Err(GatewayError::NotFound(format!("target {id} not found")));
            }
            Ok(Target {
                id: id.to_string(),
                name: "Mock Target".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
                exclude_hosts: vec![],
                alive_test: None,
                port_list: None,
                reverse_lookup_only: false,
                reverse_lookup_unify: false,
                ssh_credential: None,
                smb_credential: None,
                esxi_credential: None,
                snmp_credential: None,
                in_use: false,
                writable: true,
            })
        }

        async fn modify_target(
            &self,
            _session_token: &str,
            id: &str,
            input: ModifyTargetInput,
        ) -> Result<Target, GatewayError> {
            if self.should_fail {
                return Err(GatewayError::NotFound(format!("target {id} not found")));
            }
            Ok(Target {
                id: id.to_string(),
                name: input.name.unwrap_or_else(|| "Modified Target".to_string()),
                comment: input.comment,
                hosts: input.hosts.unwrap_or_else(|| vec!["10.0.0.1".to_string()]),
                exclude_hosts: input.exclude_hosts.unwrap_or_default(),
                alive_test: input.alive_test,
                port_list: None,
                reverse_lookup_only: false,
                reverse_lookup_unify: false,
                ssh_credential: None,
                smb_credential: None,
                esxi_credential: None,
                snmp_credential: None,
                in_use: false,
                writable: true,
            })
        }

        async fn delete_target(&self, _session_token: &str, id: &str) -> Result<(), GatewayError> {
            if self.should_fail {
                return Err(GatewayError::NotFound(format!("target {id} not found")));
            }
            Ok(())
        }
    }

    // Mock task port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockTaskPort;

    #[async_trait]
    impl TaskPort for MockTaskPort {
        async fn list_tasks(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
            Ok(TaskPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
            Ok("00000000-0000-0000-0000-000000000001".to_string())
        }

        async fn get_task(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
            Err(GatewayError::NotFound(format!("task {id} not found")))
        }

        async fn modify_task(
            &self,
            _: &str,
            id: &str,
            input: ModifyTaskInput,
        ) -> Result<Task, GatewayError> {
            Ok(Task {
                id: id.to_string(),
                name: input.name.unwrap_or_else(|| "Modified Task".to_string()),
                comment: input.comment,
                status: "New".to_string(),
                target: None,
                scan_config: None,
                scanner: None,
                schedule: None,
                alerts: vec![],
                alterable: None,
                hosts_ordering: input.hosts_ordering,
                observers: input.observers,
                schedule_periods: input.schedule_periods,
                last_report: None,
                current_report: None,
                result_count: None,
                in_use: false,
                writable: true,
            })
        }

        async fn delete_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
            Ok(())
        }

        async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
            Ok(TaskAction {
                report_id: "00000000-0000-0000-0000-000000000002".to_string(),
            })
        }

        async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
            Ok(())
        }

        async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
            Ok(TaskAction {
                report_id: "00000000-0000-0000-0000-000000000003".to_string(),
            })
        }
    }

    // Mock auth port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockAuthPort {
        pub(crate) should_fail: bool,
        pub(crate) disconnect_should_fail: bool,
        pub(crate) disconnected: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl AuthPort for MockAuthPort {
        async fn authenticate_session(
            &self,
            _session_token: &str,
            _username: &str,
            _password: &str,
        ) -> Result<(), GatewayError> {
            if self.should_fail {
                return Err(GatewayError::Unauthorized(
                    "invalid credentials".to_string(),
                ));
            }
            Ok(())
        }

        async fn disconnect_session(&self, session_token: &str) -> Result<(), GatewayError> {
            if self.disconnect_should_fail {
                return Err(GatewayError::BackendUnavailable(
                    "disconnect failed".to_string(),
                ));
            }
            self.disconnected
                .lock()
                .unwrap()
                .push(session_token.to_string());
            Ok(())
        }
    }

    // Mock report port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockReportPort;

    #[async_trait]
    impl ReportPort for MockReportPort {
        async fn list_reports(
            &self,
            _: &str,
            query: &ReportQuery,
        ) -> Result<ReportPage, GatewayError> {
            Ok(ReportPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn get_report(
            &self,
            _: &str,
            id: &str,
            _: &GetReportOpts,
        ) -> Result<Report, GatewayError> {
            Err(GatewayError::NotFound(format!("report {id} not found")))
        }

        async fn delete_report(&self, _: &str, id: &str) -> Result<(), GatewayError> {
            Err(GatewayError::NotFound(format!("report {id} not found")))
        }

        async fn get_report_results(
            &self,
            _: &str,
            _: &str,
            query: &ResultQuery,
        ) -> Result<ResultPage, GatewayError> {
            Ok(ResultPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }
    }

    // Mock result port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockResultPort;

    #[async_trait]
    impl ResultPort for MockResultPort {
        async fn list_results(
            &self,
            _: &str,
            query: &ResultQuery,
        ) -> Result<ResultPage, GatewayError> {
            Ok(ResultPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn get_result(&self, _: &str, id: &str) -> Result<ScanResult, GatewayError> {
            Err(GatewayError::NotFound(format!("result {id} not found")))
        }
    }

    // Mock scan config port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockScanConfigPort;

    #[async_trait]
    impl ScanConfigPort for MockScanConfigPort {
        async fn list_scan_configs(
            &self,
            _: &str,
            query: &ScanConfigQuery,
        ) -> Result<ScanConfigPage, GatewayError> {
            Ok(ScanConfigPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn create_scan_config(
            &self,
            _: &str,
            _: CreateScanConfigInput,
        ) -> Result<String, GatewayError> {
            Ok("mock-scan-config-id".to_string())
        }

        async fn get_scan_config(&self, _: &str, id: &str) -> Result<ScanConfig, GatewayError> {
            Err(GatewayError::NotFound(format!(
                "scan config {id} not found"
            )))
        }

        async fn modify_scan_config(
            &self,
            _: &str,
            id: &str,
            _: ModifyScanConfigInput,
        ) -> Result<ScanConfig, GatewayError> {
            Err(GatewayError::NotFound(format!(
                "scan config {id} not found"
            )))
        }

        async fn delete_scan_config(&self, _: &str, id: &str) -> Result<(), GatewayError> {
            Err(GatewayError::NotFound(format!(
                "scan config {id} not found"
            )))
        }
    }

    // Mock scanner port for testing
    #[derive(Clone, Default)]
    pub(crate) struct MockScannerPort;

    #[async_trait]
    impl ScannerPort for MockScannerPort {
        async fn list_scanners(
            &self,
            _: &str,
            query: &ScannerQuery,
        ) -> Result<ScannerPage, GatewayError> {
            Ok(ScannerPage {
                data: vec![],
                pagination: gvm_gateway_domain::Pagination {
                    page: query.page,
                    per_page: query.per_page,
                    total: 0,
                    total_pages: 0,
                },
            })
        }

        async fn get_scanner(&self, _: &str, id: &str) -> Result<Scanner, GatewayError> {
            Err(GatewayError::NotFound(format!("scanner {id} not found")))
        }
    }

    pub(crate) fn create_test_service() -> GatewayService {
        GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
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
        )
    }

    #[derive(Clone, Default)]
    struct TestWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> fmt::MakeWriter<'a> for TestWriter {
        type Writer = TestWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            TestWriterGuard {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct TestWriterGuard {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for TestWriterGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn capture_tracing() -> Arc<Mutex<Vec<u8>>> {
        static WRITER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        static INIT: OnceLock<()> = OnceLock::new();

        let buffer = WRITER
            .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
            .clone();
        buffer.lock().unwrap().clear();

        INIT.get_or_init(|| {
            let writer = TestWriter {
                buffer: buffer.clone(),
            };
            let subscriber = tracing_subscriber::registry()
                .with(EnvFilter::new("info"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(writer)
                        .with_ansi(false)
                        .with_span_events(FmtSpan::CLOSE),
                );
            let _ = tracing::subscriber::set_global_default(subscriber);
        });

        buffer
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    // ------------------------------------------------------------------------
    // GatewayService tests
    // ------------------------------------------------------------------------

    #[test]
    fn service_health_always_returns_ok() {
        let service = create_test_service();
        let health = service.health();
        assert_eq!(health.status, "ok");
    }

    #[test]
    fn service_ready_returns_readiness() {
        let service = create_test_service();
        let ready = service.ready().unwrap();
        assert_eq!(ready.status, "ready");
        assert!(ready.reason.is_none());
    }

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

    #[test]
    fn service_version_returns_api_and_gmp_version() {
        let service = create_test_service();
        let version = service.version().unwrap();
        assert_eq!(version.gmp_version, "22.7");
        assert!(!version.api_version.is_empty());
    }

    #[tokio::test]
    async fn service_list_targets_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .list_targets("invalid-token", TargetQuery::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn service_list_targets_with_valid_session() {
        let service = create_test_service();
        let session = service.session_manager().create("admin").unwrap();
        let result = service
            .list_targets(&session.token, TargetQuery::default())
            .await;
        assert!(result.is_ok());
    }

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

    #[tokio::test]
    async fn service_get_target_requires_valid_session() {
        let service = create_test_service();
        let result = service.get_target("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn service_modify_target_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .modify_target("invalid-token", "some-id", ModifyTargetInput::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn service_delete_target_requires_valid_session() {
        let service = create_test_service();
        let result = service.delete_target("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

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

    // ------------------------------------------------------------------------
    // Report use-case tests
    // ------------------------------------------------------------------------

    /// list_reports requires a valid session token.
    #[tokio::test]
    async fn service_list_reports_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .list_reports("invalid-token", ReportQuery::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// list_reports succeeds with a valid session.
    #[tokio::test]
    async fn service_list_reports_with_valid_session() {
        let service = create_test_service();
        let session = service.session_manager().create("admin").unwrap();
        let result = service
            .list_reports(&session.token, ReportQuery::default())
            .await;
        assert!(result.is_ok());
    }

    /// get_report requires a valid session token.
    #[tokio::test]
    async fn service_get_report_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .get_report("invalid-token", "some-id", GetReportOpts::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// delete_report requires a valid session token.
    #[tokio::test]
    async fn service_delete_report_requires_valid_session() {
        let service = create_test_service();
        let result = service.delete_report("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    // ------------------------------------------------------------------------
    // Result use-case tests
    // ------------------------------------------------------------------------

    /// list_results requires a valid session token.
    #[tokio::test]
    async fn service_list_results_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .list_results("invalid-token", ResultQuery::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// list_results succeeds with a valid session.
    #[tokio::test]
    async fn service_list_results_with_valid_session() {
        let service = create_test_service();
        let session = service.session_manager().create("admin").unwrap();
        let result = service
            .list_results(&session.token, ResultQuery::default())
            .await;
        assert!(result.is_ok());
    }

    /// get_result requires a valid session token.
    #[tokio::test]
    async fn service_get_result_requires_valid_session() {
        let service = create_test_service();
        let result = service.get_result("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// report/result operations fail with an expired session.
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

    #[tokio::test]
    async fn audit_logs_redact_sensitive_fields_and_record_session_creation_failure() {
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

    #[tokio::test]
    async fn audit_logs_command_execution_and_session_expiry_events() {
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

    #[tokio::test]
    async fn spans_are_emitted_for_session_and_command_lifecycle() {
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
}
