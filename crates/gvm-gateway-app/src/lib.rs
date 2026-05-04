// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

use std::sync::Arc;

use gvm_gateway_domain::{
    AuthPort, CreateScanConfigInput, CreateTargetInput, GatewayError, HealthStatus,
    ModifyScanConfigInput, ModifyTargetInput, ReadinessStatus, ScanConfig, ScanConfigPage,
    ScanConfigPort, ScanConfigQuery, Scanner, ScannerPage, ScannerPort, ScannerQuery,
    SessionCreated, SessionInfo, SessionManager, SystemPort, Target, TargetPage, TargetPort,
    TargetQuery, VersionInfo,
};

/// Application services exposed to adapters.
pub struct GatewayService<S, T, A, SC, SN> {
    system: Arc<S>,
    targets: Arc<T>,
    auth: Arc<A>,
    scan_configs: Arc<SC>,
    scanners: Arc<SN>,
    sessions: Arc<SessionManager>,
}

impl<S, T, A, SC, SN> GatewayService<S, T, A, SC, SN> {
    /// Creates a new service backed by the provided ports.
    pub fn new(
        system: Arc<S>,
        targets: Arc<T>,
        auth: Arc<A>,
        scan_configs: Arc<SC>,
        scanners: Arc<SN>,
    ) -> Self {
        Self {
            system,
            targets,
            auth,
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

impl<S, T, A, SC, SN> Clone for GatewayService<S, T, A, SC, SN> {
    fn clone(&self) -> Self {
        Self {
            system: Arc::clone(&self.system),
            targets: Arc::clone(&self.targets),
            auth: Arc::clone(&self.auth),
            scan_configs: Arc::clone(&self.scan_configs),
            scanners: Arc::clone(&self.scanners),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<S, T, A, SC, SN> GatewayService<S, T, A, SC, SN>
where
    S: SystemPort,
    T: TargetPort,
    A: AuthPort,
    SC: ScanConfigPort,
    SN: ScannerPort,
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
        self.scan_configs
            .get_scan_config(&session.token, id)
            .await
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
        self.scanners
            .list_scanners(&session.token, &query)
            .await
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

    // Mock scan config port for testing
    #[derive(Clone, Default)]
    struct MockScanConfigPort;

    #[async_trait]
    impl ScanConfigPort for MockScanConfigPort {
        async fn list_scan_configs(
            &self,
            _session_token: &str,
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
            _session_token: &str,
            _input: CreateScanConfigInput,
        ) -> Result<String, GatewayError> {
            Ok("mock-config-id".to_string())
        }

        async fn get_scan_config(
            &self,
            _session_token: &str,
            id: &str,
        ) -> Result<ScanConfig, GatewayError> {
            Ok(ScanConfig {
                id: id.to_string(),
                name: "Mock Config".to_string(),
                comment: None,
                family_count: None,
                nvt_count: None,
                config_type: None,
                in_use: false,
                writable: true,
            })
        }

        async fn modify_scan_config(
            &self,
            _session_token: &str,
            id: &str,
            input: ModifyScanConfigInput,
        ) -> Result<ScanConfig, GatewayError> {
            Ok(ScanConfig {
                id: id.to_string(),
                name: input.name.unwrap_or_else(|| "Modified Config".to_string()),
                comment: input.comment,
                family_count: None,
                nvt_count: None,
                config_type: None,
                in_use: false,
                writable: true,
            })
        }

        async fn delete_scan_config(
            &self,
            _session_token: &str,
            _id: &str,
        ) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    // Mock scanner port for testing
    #[derive(Clone, Default)]
    struct MockScannerPort;

    #[async_trait]
    impl ScannerPort for MockScannerPort {
        async fn list_scanners(
            &self,
            _session_token: &str,
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

        async fn get_scanner(
            &self,
            _session_token: &str,
            id: &str,
        ) -> Result<Scanner, GatewayError> {
            Ok(Scanner {
                id: id.to_string(),
                name: "Mock Scanner".to_string(),
                comment: None,
                host: None,
                port: None,
                scanner_type: None,
            })
        }
    }

    fn create_test_service() -> GatewayService<MockSystemPort, MockTargetPort, MockAuthPort, MockScanConfigPort, MockScannerPort> {
        GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
                gmp_version: "22.7".to_string(),
            }),
            Arc::new(MockTargetPort::default()),
            Arc::new(MockAuthPort::default()),
            Arc::new(MockScanConfigPort::default()),
            Arc::new(MockScannerPort::default()),
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
            Arc::new(MockAuthPort::default()),
            Arc::new(MockScanConfigPort::default()),
            Arc::new(MockScannerPort::default()),
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
            Arc::new(MockAuthPort { should_fail: true }),
            Arc::new(MockScanConfigPort::default()),
            Arc::new(MockScannerPort::default()),
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
    // Scan config use-case tests
    // ------------------------------------------------------------------------

    /// list_scan_configs requires a valid session.
    #[tokio::test]
    async fn service_list_scan_configs_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .list_scan_configs("invalid-token", ScanConfigQuery::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// list_scan_configs succeeds with a valid session.
    #[tokio::test]
    async fn service_list_scan_configs_with_valid_session() {
        let service = create_test_service();
        let session = service.session_manager().create("admin").unwrap();
        let result = service
            .list_scan_configs(&session.token, ScanConfigQuery::default())
            .await;
        assert!(result.is_ok());
    }

    /// get_scan_config requires a valid session.
    #[tokio::test]
    async fn service_get_scan_config_requires_valid_session() {
        let service = create_test_service();
        let result = service.get_scan_config("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    // ------------------------------------------------------------------------
    // Scanner use-case tests
    // ------------------------------------------------------------------------

    /// list_scanners requires a valid session.
    #[tokio::test]
    async fn service_list_scanners_requires_valid_session() {
        let service = create_test_service();
        let result = service
            .list_scanners("invalid-token", ScannerQuery::default())
            .await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// list_scanners succeeds with a valid session.
    #[tokio::test]
    async fn service_list_scanners_with_valid_session() {
        let service = create_test_service();
        let session = service.session_manager().create("admin").unwrap();
        let result = service
            .list_scanners(&session.token, ScannerQuery::default())
            .await;
        assert!(result.is_ok());
    }

    /// get_scanner requires a valid session.
    #[tokio::test]
    async fn service_get_scanner_requires_valid_session() {
        let service = create_test_service();
        let result = service.get_scanner("invalid-token", "some-id").await;
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }
}
