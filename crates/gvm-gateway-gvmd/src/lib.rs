// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! gvmd adapter implementations for the gateway.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::{
    target_from_gmp, AuthPort, CreateScanConfigInput, CreateTargetInput, GatewayError,
    ModifyScanConfigInput, ModifyTargetInput, Pagination, ReadinessStatus, ScanConfig,
    ScanConfigPage, ScanConfigPort, ScanConfigQuery, Scanner, ScannerPage, ScannerPort,
    ScannerQuery, SystemPort, Target, TargetPage, TargetPort, TargetQuery,
};
use gvm_gmp::{
    commands::{
        authentication::authenticate,
        targets::{
            create_target, delete_target, get_target, get_targets, modify_target, CreateTargetOpts,
            GetTargetsOpts, ModifyTargetOpts,
        },
    },
    responses::{ActionResponse, CreateTargetResponse, GetTargetsResponse},
    AliveTest, EntityId,
};
use tokio::sync::Mutex as AsyncMutex;

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
    async fn list_scanners(
        &self,
        _: &str,
        _: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
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

type SharedClient = Arc<AsyncMutex<GmpClient<UnixSocketConnection>>>;

/// gvmd adapter backed by session-keyed GMP clients.
#[derive(Clone, Debug)]
pub struct GvmdAdapter {
    socket_path: PathBuf,
    sessions: Arc<Mutex<HashMap<String, SharedClient>>>,
}

impl GvmdAdapter {
    /// Create a Unix-socket adapter.
    pub fn unix_socket(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Open and authenticate a session-bound GMP connection.
    pub async fn connect_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        let connection = UnixSocketConnection::with_path(&self.socket_path);
        let mut client = GmpClient::connect(connection)
            .await
            .map_err(map_gvm_error)?;
        client
            .call(authenticate(username, password))
            .await
            .map_err(map_gvm_error)?;

        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .insert(session_token.to_string(), Arc::new(AsyncMutex::new(client)));

        Ok(())
    }

    fn session_client(&self, session_token: &str) -> Result<SharedClient, GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .get(session_token)
            .cloned()
            .ok_or_else(|| GatewayError::Unauthorized("missing gvmd session".to_string()))
    }
}

#[async_trait]
impl TargetPort for GvmdAdapter {
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_targets(GetTargetsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(target_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(TargetPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        reject_unsupported_credentials(&input)?;
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_target(
                &input.name,
                CreateTargetOpts {
                    comment: input.comment,
                    hosts: input.hosts,
                    exclude_hosts: input.exclude_hosts,
                    alive_test: input
                        .alive_test
                        .as_deref()
                        .map(parse_alive_test)
                        .transpose()?,
                    port_list_id: input
                        .port_list_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                    reverse_lookup_only: input.reverse_lookup_only,
                    reverse_lookup_unify: input.reverse_lookup_unify,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateTargetResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_target(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(target_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("target {id} not found")))
    }

    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        let client = self.session_client(session_token)?;
        let target_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await
            .call(modify_target(
                &target_id,
                ModifyTargetOpts {
                    name: input.name,
                    comment: input.comment,
                    hosts: input.hosts.unwrap_or_default(),
                    exclude_hosts: input.exclude_hosts.unwrap_or_default(),
                    alive_test: input
                        .alive_test
                        .as_deref()
                        .map(parse_alive_test)
                        .transpose()?,
                    port_list_id: input
                        .port_list_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_target(session_token, id).await
    }

    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_target(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl AuthPort for GvmdAdapter {
    async fn authenticate_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        self.connect_session(session_token, username, password)
            .await
    }

    async fn disconnect_session(&self, session_token: &str) -> Result<(), GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .remove(session_token);
        Ok(())
    }
}

#[async_trait]
impl ScanConfigPort for GvmdAdapter {
    async fn list_scan_configs(
        &self,
        _: &str,
        _: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scan config GMP commands not yet available in rust-gvm".to_string(),
        ))
    }

    async fn create_scan_config(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scan config GMP commands not yet available in rust-gvm".to_string(),
        ))
    }

    async fn get_scan_config(&self, _: &str, _: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scan config GMP commands not yet available in rust-gvm".to_string(),
        ))
    }

    async fn modify_scan_config(
        &self,
        _: &str,
        _: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scan config GMP commands not yet available in rust-gvm".to_string(),
        ))
    }

    async fn delete_scan_config(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scan config GMP commands not yet available in rust-gvm".to_string(),
        ))
    }
}

#[async_trait]
impl ScannerPort for GvmdAdapter {
    async fn list_scanners(
        &self,
        _: &str,
        _: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scanner GMP commands not yet available in rust-gvm".to_string(),
        ))
    }

    async fn get_scanner(&self, _: &str, _: &str) -> Result<Scanner, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "scanner GMP commands not yet available in rust-gvm".to_string(),
        ))
    }
}

fn reject_unsupported_credentials(input: &CreateTargetInput) -> Result<(), GatewayError> {
    if input.ssh_credential_id.is_some()
        || input.smb_credential_id.is_some()
        || input.esxi_credential_id.is_some()
        || input.snmp_credential_id.is_some()
    {
        return Err(GatewayError::InvalidInput(
            "credential references are not supported by rust-gvm target commands yet".to_string(),
        ));
    }
    Ok(())
}

fn parse_entity_id(value: &str) -> Result<EntityId, GatewayError> {
    EntityId::new(value).map_err(|_| GatewayError::InvalidInput(format!("invalid UUID: {value}")))
}

fn parse_alive_test(value: &str) -> Result<AliveTest, GatewayError> {
    AliveTest::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid aliveTest: {value}")))
}

/// Classify a gvmd client error into a protocol-agnostic domain error.
pub fn map_gvm_error(error: gvm_client::GvmError) -> GatewayError {
    match error {
        gvm_client::GvmError::Server {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_client::GvmError::Server {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        gvm_client::GvmError::Server {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_client::GvmError::Timeout(duration) => {
            GatewayError::BackendUnavailable(format!("gvmd timeout after {duration:?}"))
        }
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

/// Classify a GMP parse failure into a protocol-agnostic domain error.
pub fn map_parse_error(error: gvm_gmp::responses::ParseError) -> GatewayError {
    match error {
        gvm_gmp::responses::ParseError::ServerError {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // StaticGvmdAdapter tests
    // ------------------------------------------------------------------------

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

    // ------------------------------------------------------------------------
    // GvmdAdapter unit tests (non-integration)
    // ------------------------------------------------------------------------

    #[test]
    fn gvmd_adapter_session_client_fails_without_session() {
        let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
        let result = adapter.session_client("missing-token");
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    // ------------------------------------------------------------------------
    // Helper function tests
    // ------------------------------------------------------------------------

    #[test]
    fn parse_entity_id_valid() {
        let result = parse_entity_id("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_entity_id_invalid_empty() {
        let result = parse_entity_id("");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn parse_entity_id_invalid_special_chars() {
        let result = parse_entity_id("invalid@id");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn parse_alive_test_valid() {
        let result = parse_alive_test("ICMP Ping");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_alive_test_invalid() {
        let result = parse_alive_test("InvalidTest");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn reject_unsupported_credentials_passes_empty() {
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
        assert!(reject_unsupported_credentials(&input).is_ok());
    }

    #[test]
    fn reject_unsupported_credentials_fails_ssh() {
        let input = CreateTargetInput {
            name: "test".to_string(),
            comment: None,
            hosts: vec!["127.0.0.1".to_string()],
            exclude_hosts: vec![],
            alive_test: None,
            port_list_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            ssh_credential_id: Some("cred-id".to_string()),
            smb_credential_id: None,
            esxi_credential_id: None,
            snmp_credential_id: None,
        };
        assert!(matches!(
            reject_unsupported_credentials(&input),
            Err(GatewayError::InvalidInput(_))
        ));
    }

    #[test]
    fn reject_unsupported_credentials_fails_smb() {
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
            smb_credential_id: Some("cred-id".to_string()),
            esxi_credential_id: None,
            snmp_credential_id: None,
        };
        assert!(matches!(
            reject_unsupported_credentials(&input),
            Err(GatewayError::InvalidInput(_))
        ));
    }

    // ------------------------------------------------------------------------
    // Error mapping tests
    // ------------------------------------------------------------------------

    #[test]
    fn map_gvm_error_400_to_invalid_input() {
        let error = gvm_client::GvmError::Server {
            status: 400,
            message: "bad request".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::InvalidInput(_)));
    }

    #[test]
    fn map_gvm_error_401_to_unauthorized() {
        let error = gvm_client::GvmError::Server {
            status: 401,
            message: "unauthorized".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::Unauthorized(_)));
    }

    #[test]
    fn map_gvm_error_404_to_not_found() {
        let error = gvm_client::GvmError::Server {
            status: 404,
            message: "not found".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::NotFound(_)));
    }

    #[test]
    fn map_parse_error_404_to_not_found() {
        let error = gvm_gmp::responses::ParseError::ServerError {
            status: 404,
            message: "not found".to_string(),
        };
        let mapped = map_parse_error(error);
        assert!(matches!(mapped, GatewayError::NotFound(_)));
    }

    #[test]
    fn map_parse_error_400_to_invalid_input() {
        let error = gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message: "bad request".to_string(),
        };
        let mapped = map_parse_error(error);
        assert!(matches!(mapped, GatewayError::InvalidInput(_)));
    }

    // ------------------------------------------------------------------------
    // GvmdAdapter integration tests (using mock server)
    // ------------------------------------------------------------------------

    mod integration {
        use super::*;
        use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, Resource, ServerMode};

        async fn create_mock_adapter() -> (GvmdAdapter, MockGmpServer, String) {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-session-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            (adapter, server, token.to_string())
        }

        #[tokio::test]
        async fn gvmd_adapter_connect_session_success() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let result = adapter.connect_session("token", "admin", "admin").await;

            assert!(result.is_ok());
            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_empty() {
            let (adapter, server, token) = create_mock_adapter().await;

            let result = adapter
                .list_targets(
                    &token,
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert!(page.data.is_empty());
            assert_eq!(page.pagination.total, 0);

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_create_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            let input = CreateTargetInput {
                name: "Test Target".to_string(),
                comment: Some("Integration test".to_string()),
                hosts: vec!["192.168.1.1".to_string()],
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

            let result = adapter.create_target(&token, input).await;

            assert!(result.is_ok());
            let id = result.unwrap();
            assert!(!id.is_empty());

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Get Me".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
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
            let id = adapter.create_target(&token, input).await.unwrap();

            // Fetch the target
            let result = adapter.get_target(&token, &id).await;

            assert!(result.is_ok());
            let target = result.unwrap();
            assert_eq!(target.name, "Get Me");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_target_not_found() {
            let (adapter, server, token) = create_mock_adapter().await;

            let result = adapter
                .get_target(&token, "550e8400-e29b-41d4-a716-446655440000")
                .await;

            assert!(matches!(result, Err(GatewayError::NotFound(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_modify_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Before Modify".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
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
            let id = adapter.create_target(&token, input).await.unwrap();

            // Modify the target
            let modify_input = ModifyTargetInput {
                name: Some("After Modify".to_string()),
                comment: Some("Updated".to_string()),
                hosts: Some(vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()]),
                exclude_hosts: None,
                alive_test: None,
                port_list_id: None,
            };
            let result = adapter.modify_target(&token, &id, modify_input).await;

            assert!(result.is_ok());
            let target = result.unwrap();
            assert_eq!(target.name, "After Modify");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_delete_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Delete Me".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
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
            let id = adapter.create_target(&token, input).await.unwrap();

            // Delete the target
            let result = adapter.delete_target(&token, &id).await;

            assert!(result.is_ok());

            // Verify it's gone
            let get_result = adapter.get_target(&token, &id).await;
            assert!(matches!(get_result, Err(GatewayError::NotFound(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_paginated() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .seed(|store| {
                    for i in 1..=15 {
                        let mut resource = Resource::new("target", &format!("Target-{i:02}"));
                        resource.set_attr("hosts", &format!("10.0.0.{i}"));
                        store.create(resource);
                    }
                })
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            let result = adapter
                .list_targets(
                    token,
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 10,
                    },
                )
                .await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert_eq!(page.data.len(), 10);
            assert_eq!(page.pagination.total, 15);
            assert_eq!(page.pagination.total_pages, 2);

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_unauthorized() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            // Don't authenticate

            let result = adapter
                .list_targets(
                    "unauthed-token",
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;

            assert!(matches!(result, Err(GatewayError::Unauthorized(_))));

            server.shutdown().await;
        }
    }
}
