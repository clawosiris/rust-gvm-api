// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

use std::sync::Arc;

use gvm_gateway_domain::{
    AuthPort, CreateScanConfigInput, CreateTargetInput, CreateTaskInput, GatewayError,
    GetReportOpts, HealthStatus, ModifyScanConfigInput, ModifyTargetInput, ModifyTaskInput,
    ReadinessStatus, Report, ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort,
    ResultQuery, ScanConfig, ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner,
    ScannerPage, ScannerPort, ScannerQuery, SessionCreated, SessionInfo, SessionManager, SystemPort,
    Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery,
    VersionInfo,
};

/// Application services exposed to adapters.
pub struct GatewayService<S, T, K, A, R, Re, Sc = (), Sn = ()> {
    system: Arc<S>,
    targets: Arc<T>,
    tasks: Arc<K>,
    auth: Arc<A>,
    reports: Arc<R>,
    results: Arc<Re>,
    scan_configs: Arc<Sc>,
    scanners: Arc<Sn>,
    sessions: Arc<SessionManager>,
}

impl<S, T, K, A, R, Re> GatewayService<S, T, K, A, R, Re> {
    /// Creates a new service backed by the provided ports.
    pub fn new(
        system: Arc<S>,
        targets: Arc<T>,
        tasks: Arc<K>,
        auth: Arc<A>,
        reports: Arc<R>,
        results: Arc<Re>,
    ) -> Self {
        Self {
            system,
            targets,
            tasks,
            auth,
            reports,
            results,
            scan_configs: Arc::new(()),
            scanners: Arc::new(()),
            sessions: Arc::new(SessionManager::default()),
        }
    }
}

impl<S, T, K, A, R, Re, Sc, Sn> GatewayService<S, T, K, A, R, Re, Sc, Sn> {
    /// Creates a new service backed by the provided ports, including scan configs and scanners.
    pub fn with_all(
        system: Arc<S>,
        targets: Arc<T>,
        tasks: Arc<K>,
        auth: Arc<A>,
        reports: Arc<R>,
        results: Arc<Re>,
        scan_configs: Arc<Sc>,
        scanners: Arc<Sn>,
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
            sessions: Arc::new(SessionManager::default()),
        }
    }

    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }
}

impl<S, T, K, A, R, Re, Sc, Sn> Clone for GatewayService<S, T, K, A, R, Re, Sc, Sn> {
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

impl<S, T, K, A, R, Re, Sc, Sn> GatewayService<S, T, K, A, R, Re, Sc, Sn>
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: Send + Sync + 'static,
    Re: Send + Sync + 'static,
    Sc: Send + Sync + 'static,
    Sn: Send + Sync + 'static,
{
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
    // Session lifecycle
    // ------------------------------------------------------------------

    /// Authenticates with the supplied credentials, creates a domain session,
    /// and establishes a backend connection bound to the new token.
    pub async fn create_session(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionCreated, GatewayError> {
        let session = self.sessions.create(username)?;
        if let Err(err) = self
            .auth
            .authenticate_session(&session.token, username, password)
            .await
        {
            // Roll back the domain session when backend auth fails.
            let _ = self.sessions.remove(&session.token);
            return Err(err);
        }
        let gmp_version = self.system.gmp_version()?;
        Ok(SessionCreated {
            token: session.token,
            expires_in: self.sessions.idle_timeout_secs(),
            gmp_version,
        })
    }

    /// Returns detailed session information without extending the idle timer.
    pub fn get_session(&self, token: &str) -> Result<SessionInfo, GatewayError> {
        self.sessions.get_info(token)
    }

    /// Closes and destroys a session, disconnecting the backend connection.
    pub async fn delete_session(&self, token: &str) -> Result<(), GatewayError> {
        let removed = self.sessions.remove(token)?;
        if removed.is_none() {
            return Err(GatewayError::NotFound("session not found".to_string()));
        }
        // Best-effort backend disconnect; ignore errors.
        let _ = self.auth.disconnect_session(token).await;
        Ok(())
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
        let session = self.sessions.touch(session_token)?;
        self.targets.list_targets(&session.token, &query).await
    }

    /// Creates a new target for an authenticated session.
    pub async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.create_target(&session.token, input).await
    }

    /// Fetches a target for an authenticated session.
    pub async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.get_target(&session.token, id).await
    }

    /// Modifies a target for an authenticated session.
    pub async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.modify_target(&session.token, id, input).await
    }

    /// Deletes a target for an authenticated session.
    pub async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.delete_target(&session.token, id).await
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
        let session = self.sessions.touch(session_token)?;
        self.tasks.list_tasks(&session.token, &query).await
    }

    /// Creates a new task for an authenticated session.
    pub async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.create_task(&session.token, input).await
    }

    /// Fetches a task for an authenticated session.
    pub async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.get_task(&session.token, id).await
    }

    /// Modifies a task for an authenticated session.
    pub async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.modify_task(&session.token, id, input).await
    }

    /// Deletes a task for an authenticated session.
    pub async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.delete_task(&session.token, id).await
    }

    /// Starts a task for an authenticated session.
    pub async fn start_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.start_task(&session.token, id).await
    }

    /// Stops a running task for an authenticated session.
    pub async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.stop_task(&session.token, id).await
    }

    /// Resumes a stopped task for an authenticated session.
    pub async fn resume_task(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TaskAction, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.tasks.resume_task(&session.token, id).await
    }
}

impl<S, T, K, A, R, Re, Sc, Sn> GatewayService<S, T, K, A, R, Re, Sc, Sn>
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: Send + Sync + 'static,
    Sn: Send + Sync + 'static,
{
    // ------------------------------------------------------------------
    // Reports
    // ------------------------------------------------------------------

    /// Lists reports for an authenticated session.
    pub async fn list_reports(
        &self,
        session_token: &str,
        query: ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.reports.list_reports(&session.token, &query).await
    }

    /// Fetches a report for an authenticated session.
    pub async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: GetReportOpts,
    ) -> Result<Report, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.reports.get_report(&session.token, id, &opts).await
    }

    /// Deletes a report for an authenticated session.
    pub async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.reports.delete_report(&session.token, id).await
    }

    /// Lists results for a specific report.
    pub async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.reports
            .get_report_results(&session.token, report_id, &query)
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
        let session = self.sessions.touch(session_token)?;
        self.results.list_results(&session.token, &query).await
    }

    /// Fetches a result for an authenticated session.
    pub async fn get_result(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanResult, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.results.get_result(&session.token, id).await
    }
}

impl<S, T, K, A, R, Re, Sc, Sn> GatewayService<S, T, K, A, R, Re, Sc, Sn>
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: Send + Sync + 'static,
    Re: Send + Sync + 'static,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    // ------------------------------------------------------------------
    // Scan Configs
    // ------------------------------------------------------------------

    /// Lists scan configs for an authenticated session.
    pub async fn list_scan_configs(
        &self,
        session_token: &str,
        query: ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scan_configs
            .list_scan_configs(&session.token, &query)
            .await
    }

    /// Creates a new scan config for an authenticated session.
    pub async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scan_configs
            .create_scan_config(&session.token, input)
            .await
    }

    /// Fetches a scan config for an authenticated session.
    pub async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scan_configs.get_scan_config(&session.token, id).await
    }

    /// Modifies a scan config for an authenticated session.
    pub async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scan_configs
            .modify_scan_config(&session.token, id, input)
            .await
    }

    /// Deletes a scan config for an authenticated session.
    pub async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scan_configs
            .delete_scan_config(&session.token, id)
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
        let session = self.sessions.touch(session_token)?;
        self.scanners.list_scanners(&session.token, &query).await
    }

    /// Fetches a scanner for an authenticated session.
    pub async fn get_scanner(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Scanner, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.scanners.get_scanner(&session.token, id).await
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    // Mock system port for testing
    #[derive(Clone)]
    struct MockSystemPort {
        ready: bool,
        gmp_version: String,
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
    struct MockTargetPort {
        should_fail: bool,
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
    struct MockTaskPort;

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
    struct MockAuthPort {
        should_fail: bool,
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

        async fn disconnect_session(&self, _session_token: &str) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    // Mock report port for testing
    #[derive(Clone, Default)]
    struct MockReportPort;

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
    struct MockResultPort;

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

    fn create_test_service() -> GatewayService<
        MockSystemPort,
        MockTargetPort,
        MockTaskPort,
        MockAuthPort,
        MockReportPort,
        MockResultPort,
    > {
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
        )
    }

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

    #[test]
    fn service_session_manager_shared() {
        let service = create_test_service();
        let manager1 = service.session_manager();
        let manager2 = service.session_manager();

        let session = manager1.create("user").unwrap();
        let found = manager2.get(&session.token).unwrap();
        assert!(found.is_some());
    }

    #[test]
    fn service_clone_shares_state() {
        let service = create_test_service();
        let cloned = service.clone();

        let session = service.session_manager().create("user").unwrap();
        let found = cloned.session_manager().get(&session.token).unwrap();
        assert!(found.is_some());
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
    // Session lifecycle use-case tests
    // ------------------------------------------------------------------------

    /// create_session returns a token, idle timeout, and GMP version
    /// when backend authentication succeeds.
    #[tokio::test]
    async fn service_create_session_success() {
        let service = create_test_service();
        let created = service.create_session("admin", "secret").await.unwrap();

        assert!(created.token.starts_with("gvm_sess_"));
        assert_eq!(created.expires_in, 300);
        assert_eq!(created.gmp_version, "22.7");
    }

    /// create_session rolls back the domain session when backend auth fails.
    #[tokio::test]
    async fn service_create_session_auth_failure_rolls_back() {
        let service = GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
                gmp_version: "22.7".to_string(),
            }),
            Arc::new(MockTargetPort::default()),
            Arc::new(MockTaskPort),
            Arc::new(MockAuthPort { should_fail: true }),
            Arc::new(MockReportPort),
            Arc::new(MockResultPort),
        );

        let result = service.create_session("admin", "wrong").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// get_session returns session info for an active session.
    #[tokio::test]
    async fn service_get_session_active() {
        let service = create_test_service();
        let created = service.create_session("admin", "secret").await.unwrap();
        let info = service.get_session(&created.token).unwrap();

        assert_eq!(info.token, created.token);
        assert_eq!(info.user, "admin");
        assert_eq!(info.state, "active");
        assert!(info.expires_in > 0);
    }

    /// get_session returns NotFound for unknown tokens.
    #[tokio::test]
    async fn service_get_session_not_found() {
        let service = create_test_service();
        let result = service.get_session("nonexistent");
        assert!(matches!(result, Err(GatewayError::NotFound(_))));
    }

    /// delete_session removes the session so subsequent gets fail.
    #[tokio::test]
    async fn service_delete_session_success() {
        let service = create_test_service();
        let created = service.create_session("admin", "secret").await.unwrap();

        service.delete_session(&created.token).await.unwrap();

        let result = service.get_session(&created.token);
        assert!(matches!(result, Err(GatewayError::NotFound(_))));
    }

    /// delete_session fails with NotFound for unknown tokens.
    #[tokio::test]
    async fn service_delete_session_not_found() {
        let service = create_test_service();
        let result = service.delete_session("nonexistent").await;
        assert!(matches!(result, Err(GatewayError::NotFound(_))));
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
}
