// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Domain types and ports for the GVM gateway.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod session;
pub use session::{Session, SessionManager, SessionState};

/// Liveness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthStatus {
    /// Liveness state.
    pub status: &'static str,
}

/// Readiness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessStatus {
    /// Readiness state.
    pub status: &'static str,
    /// Optional reason when not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// API and GMP version information.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    /// Gateway API version.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// GMP backend version.
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

/// Minimal reference to a related resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    /// Resource identifier.
    pub id: String,
    /// Optional resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// REST target representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Target {
    /// Target identifier.
    pub id: String,
    /// Target name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    #[serde(
        rename = "excludeHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude_hosts: Vec<String>,
    /// Optional alive-test strategy.
    #[serde(rename = "aliveTest", skip_serializing_if = "Option::is_none")]
    pub alive_test: Option<String>,
    /// Optional port list reference.
    #[serde(rename = "portList", skip_serializing_if = "Option::is_none")]
    pub port_list: Option<ResourceRef>,
    /// Reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: bool,
    /// Reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: bool,
    /// Optional SSH credential reference.
    #[serde(rename = "sshCredential", skip_serializing_if = "Option::is_none")]
    pub ssh_credential: Option<ResourceRef>,
    /// Optional SMB credential reference.
    #[serde(rename = "smbCredential", skip_serializing_if = "Option::is_none")]
    pub smb_credential: Option<ResourceRef>,
    /// Optional ESXi credential reference.
    #[serde(rename = "esxiCredential", skip_serializing_if = "Option::is_none")]
    pub esxi_credential: Option<ResourceRef>,
    /// Optional SNMP credential reference.
    #[serde(rename = "snmpCredential", skip_serializing_if = "Option::is_none")]
    pub snmp_credential: Option<ResourceRef>,
    /// Whether the target is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the target is writable.
    pub writable: bool,
}

/// Pagination metadata for list responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pagination {
    /// Current page.
    pub page: u32,
    /// Page size.
    #[serde(rename = "perPage")]
    pub per_page: u32,
    /// Total matching resources.
    pub total: u32,
    /// Total number of pages.
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}

/// Paginated target list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetPage {
    /// Page items.
    pub data: Vec<Target>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Target list query options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Target create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTargetInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    pub exclude_hosts: Vec<String>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
    /// Optional reverse lookup only.
    pub reverse_lookup_only: Option<bool>,
    /// Optional reverse lookup unify.
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier.
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<String>,
}

/// Target update command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyTargetInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional hosts.
    pub hosts: Option<Vec<String>>,
    /// Optional excluded hosts.
    pub exclude_hosts: Option<Vec<String>>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
}

/// Application-level errors surfaced by ports and use cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// Backend service is unavailable or unhealthy.
    BackendUnavailable(String),
    /// Resource or route was not found.
    NotFound(String),
    /// Request input was invalid.
    InvalidInput(String),
    /// Session or credentials were invalid.
    Unauthorized(String),
}

/// Port for system information needed by the gateway.
pub trait SystemPort: Send + Sync + 'static {
    /// Returns whether the backend is ready.
    fn readiness(&self) -> Result<ReadinessStatus, GatewayError>;

    /// Returns the GMP version string for the connected backend.
    fn gmp_version(&self) -> Result<String, GatewayError>;
}

/// Port for target CRUD operations.
#[async_trait]
pub trait TargetPort: Send + Sync + 'static {
    /// List targets for the session.
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError>;

    /// Create a new target.
    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a target by identifier.
    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError>;

    /// Modify a target by identifier.
    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError>;

    /// Delete a target by identifier.
    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;
}
