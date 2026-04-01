// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

use std::sync::Arc;

use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, HealthStatus, ModifyTargetInput, ReadinessStatus,
    SessionManager, SystemPort, Target, TargetPage, TargetPort, TargetQuery, VersionInfo,
};

/// Application services exposed to adapters.
pub struct GatewayService<S, T> {
    system: Arc<S>,
    targets: Arc<T>,
    sessions: Arc<SessionManager>,
}

impl<S, T> GatewayService<S, T> {
    /// Creates a new service backed by the provided ports.
    pub fn new(system: Arc<S>, targets: Arc<T>) -> Self {
        Self {
            system,
            targets,
            sessions: Arc::new(SessionManager::default()),
        }
    }

    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }
}

impl<S, T> Clone for GatewayService<S, T> {
    fn clone(&self) -> Self {
        Self {
            system: Arc::clone(&self.system),
            targets: Arc::clone(&self.targets),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<S, T> GatewayService<S, T>
where
    S: SystemPort,
    T: TargetPort,
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
    pub async fn get_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Target, GatewayError> {
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

        async fn get_target(
            &self,
            _session_token: &str,
            id: &str,
        ) -> Result<Target, GatewayError> {
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

        async fn delete_target(
            &self,
            _session_token: &str,
            id: &str,
        ) -> Result<(), GatewayError> {
            if self.should_fail {
                return Err(GatewayError::NotFound(format!("target {id} not found")));
            }
            Ok(())
        }
    }

    fn create_test_service() -> GatewayService<MockSystemPort, MockTargetPort> {
        GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
                gmp_version: "22.7".to_string(),
            }),
            Arc::new(MockTargetPort::default()),
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
}
