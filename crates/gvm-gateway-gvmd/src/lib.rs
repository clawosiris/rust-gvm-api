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
use gvm_gateway_domain::{GatewayError, ReadinessStatus, SystemPort, TargetPort};
use gvm_gateway_rest::{
    error::{map_gvm_error, map_parse_error},
    targets::{
        target_from_gmp, CreateTargetInput, ModifyTargetInput, Pagination, Target, TargetPage,
        TargetQuery,
    },
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
    type TargetQuery = TargetQuery;
    type CreateTargetInput = CreateTargetInput;
    type ModifyTargetInput = ModifyTargetInput;
    type Target = Target;
    type TargetPage = TargetPage;

    async fn list_targets(
        &self,
        _: &str,
        _: &Self::TargetQuery,
    ) -> Result<Self::TargetPage, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn create_target(
        &self,
        _: &str,
        _: Self::CreateTargetInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn get_target(&self, _: &str, _: &str) -> Result<Self::Target, GatewayError> {
        Err(GatewayError::BackendUnavailable(
            "static adapter does not support targets".to_string(),
        ))
    }

    async fn modify_target(
        &self,
        _: &str,
        _: &str,
        _: Self::ModifyTargetInput,
    ) -> Result<Self::Target, GatewayError> {
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
    type TargetQuery = TargetQuery;
    type CreateTargetInput = CreateTargetInput;
    type ModifyTargetInput = ModifyTargetInput;
    type Target = Target;
    type TargetPage = TargetPage;

    async fn list_targets(
        &self,
        session_token: &str,
        query: &Self::TargetQuery,
    ) -> Result<Self::TargetPage, GatewayError> {
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
        input: Self::CreateTargetInput,
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

    async fn get_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Self::Target, GatewayError> {
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
        input: Self::ModifyTargetInput,
    ) -> Result<Self::Target, GatewayError> {
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
