// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Target DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::handler::validate_uuid;
use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse, ResourceRefResponse},
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{
        created_json, ok_json, problem_response, CreateTargetDoc, ModifyTargetDoc,
        ResourceIdPathDoc, TargetListQueryDoc,
    },
    query::{parse_collection_query, DeleteResourceQueryParams},
};

// Re-export domain types for backward compatibility
pub use gvm_gateway_domain::{
    CreateTargetInput, ModifyTargetInput, Pagination, ResourceRef, Target, TargetPage, TargetQuery,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_string_enum! {
    /// Alive-test strategy for a target.
    pub(crate) enum AliveTest {
        ScanConfigDefault => "Scan Config Default",
        IcmpPing => "ICMP Ping",
        TcpAckServicePing => "TCP-ACK Service Ping",
        TcpSynServicePing => "TCP-SYN Service Ping",
        ArpPing => "ARP Ping",
        IcmpTcpAckServicePing => "ICMP, TCP-ACK Service Ping",
        IcmpArpPing => "ICMP, ARP Ping",
        TcpAckServiceArpPing => "TCP-ACK Service, ARP Ping",
        IcmpTcpAckServiceArpPing => "ICMP, TCP-ACK Service, ARP Ping",
        ConsiderAlive => "Consider Alive",
    }
}

/// JSON body returned for a single target.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Target")]
pub(crate) struct TargetResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    hosts: Vec<String>,
    #[serde(
        rename = "excludeHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    exclude_hosts: Vec<String>,
    #[serde(rename = "aliveTest", skip_serializing_if = "Option::is_none")]
    alive_test: Option<AliveTest>,
    #[serde(rename = "portList", skip_serializing_if = "Option::is_none")]
    port_list: Option<ResourceRefResponse>,
    #[serde(rename = "reverseLookupOnly")]
    reverse_lookup_only: bool,
    #[serde(rename = "reverseLookupUnify")]
    reverse_lookup_unify: bool,
    #[serde(rename = "sshCredential", skip_serializing_if = "Option::is_none")]
    ssh_credential: Option<ResourceRefResponse>,
    #[serde(rename = "smbCredential", skip_serializing_if = "Option::is_none")]
    smb_credential: Option<ResourceRefResponse>,
    #[serde(rename = "esxiCredential", skip_serializing_if = "Option::is_none")]
    esxi_credential: Option<ResourceRefResponse>,
    #[serde(rename = "snmpCredential", skip_serializing_if = "Option::is_none")]
    snmp_credential: Option<ResourceRefResponse>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::Target> for TargetResponse {
    fn from(t: gvm_gateway_domain::Target) -> Self {
        Self {
            id: parse_uuid(&t.id),
            name: t.name,
            comment: t.comment,
            hosts: t.hosts,
            exclude_hosts: t.exclude_hosts,
            alive_test: t.alive_test.as_deref().map(AliveTest::parse),
            port_list: t.port_list.map(ResourceRefResponse::from),
            reverse_lookup_only: t.reverse_lookup_only,
            reverse_lookup_unify: t.reverse_lookup_unify,
            ssh_credential: t.ssh_credential.map(ResourceRefResponse::from),
            smb_credential: t.smb_credential.map(ResourceRefResponse::from),
            esxi_credential: t.esxi_credential.map(ResourceRefResponse::from),
            snmp_credential: t.snmp_credential.map(ResourceRefResponse::from),
            in_use: t.in_use,
            writable: t.writable,
        }
    }
}

/// JSON body returned for a paginated list of targets.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TargetList")]
pub(crate) struct TargetListResponse {
    data: Vec<TargetResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TargetPage> for TargetListResponse {
    fn from(page: gvm_gateway_domain::TargetPage) -> Self {
        Self {
            data: page.data.into_iter().map(TargetResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-targets query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl TargetListQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// Create-target request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CreateTargetRequest {
    /// Optional name so validation can return RFC 9457 instead of extractor failures.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Excluded hosts.
    #[serde(rename = "excludeHosts", default)]
    pub exclude_hosts: Vec<String>,
    /// Optional alive test.
    #[serde(rename = "aliveTest")]
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    #[serde(rename = "portListId")]
    pub port_list_id: Option<String>,
    /// Reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: Option<bool>,
    /// Reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier. Omitted or null leaves the binding unchanged.
    #[serde(rename = "sshCredentialId")]
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier. Omitted or null leaves the binding unchanged.
    #[serde(rename = "smbCredentialId")]
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier. Omitted or null leaves the binding unchanged.
    #[serde(rename = "esxiCredentialId")]
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier. Omitted or null leaves the binding unchanged.
    #[serde(rename = "snmpCredentialId")]
    pub snmp_credential_id: Option<String>,
}

impl CreateTargetRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateTargetInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        if self.hosts.is_empty() {
            return Err(GatewayError::InvalidInput(
                "hosts must contain at least one entry".to_string(),
            ));
        }
        validate_optional_uuid("portListId", self.port_list_id.as_deref())?;
        validate_optional_uuid("sshCredentialId", self.ssh_credential_id.as_deref())?;
        validate_optional_uuid("smbCredentialId", self.smb_credential_id.as_deref())?;
        validate_optional_uuid("esxiCredentialId", self.esxi_credential_id.as_deref())?;
        validate_optional_uuid("snmpCredentialId", self.snmp_credential_id.as_deref())?;

        Ok(CreateTargetInput {
            name,
            comment: self.comment,
            hosts: self.hosts,
            exclude_hosts: self.exclude_hosts,
            alive_test: self.alive_test,
            port_list_id: self.port_list_id,
            reverse_lookup_only: self.reverse_lookup_only,
            reverse_lookup_unify: self.reverse_lookup_unify,
            ssh_credential_id: self.ssh_credential_id,
            smb_credential_id: self.smb_credential_id,
            esxi_credential_id: self.esxi_credential_id,
            snmp_credential_id: self.snmp_credential_id,
        })
    }
}

impl ValidateInto<CreateTargetInput> for CreateTargetRequest {
    fn validate_into(self) -> Result<CreateTargetInput, GatewayError> {
        self.validate()
    }
}

/// Modify-target request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModifyTargetRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional hosts.
    pub hosts: Option<Vec<String>>,
    /// Optional excluded hosts.
    #[serde(rename = "excludeHosts")]
    pub exclude_hosts: Option<Vec<String>>,
    /// Optional alive test.
    #[serde(rename = "aliveTest")]
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    #[serde(rename = "portListId")]
    pub port_list_id: Option<String>,
    /// Optional reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: Option<bool>,
    /// Optional reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier.
    #[serde(rename = "sshCredentialId")]
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier.
    #[serde(rename = "smbCredentialId")]
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier.
    #[serde(rename = "esxiCredentialId")]
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier.
    #[serde(rename = "snmpCredentialId")]
    pub snmp_credential_id: Option<String>,
}

impl ModifyTargetRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyTargetInput, GatewayError> {
        validate_optional_uuid("portListId", self.port_list_id.as_deref())?;
        validate_optional_uuid("sshCredentialId", self.ssh_credential_id.as_deref())?;
        validate_optional_uuid("smbCredentialId", self.smb_credential_id.as_deref())?;
        validate_optional_uuid("esxiCredentialId", self.esxi_credential_id.as_deref())?;
        validate_optional_uuid("snmpCredentialId", self.snmp_credential_id.as_deref())?;

        Ok(ModifyTargetInput {
            name: self.name,
            comment: self.comment,
            hosts: self.hosts,
            exclude_hosts: self.exclude_hosts,
            alive_test: self.alive_test,
            port_list_id: self.port_list_id,
            reverse_lookup_only: self.reverse_lookup_only,
            reverse_lookup_unify: self.reverse_lookup_unify,
            ssh_credential_id: self.ssh_credential_id,
            smb_credential_id: self.smb_credential_id,
            esxi_credential_id: self.esxi_credential_id,
            snmp_credential_id: self.snmp_credential_id,
        })
    }
}

impl ValidateInto<ModifyTargetInput> for ModifyTargetRequest {
    fn validate_into(self) -> Result<ModifyTargetInput, GatewayError> {
        self.validate()
    }
}

/// List targets handler.
pub async fn list_targets(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        TargetListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_targets(
                    &session,
                    TargetQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        TargetListResponse::from,
    )
    .await
}

/// Create target handler.
pub async fn create_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateTargetInput, CreateTargetRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_target(&session, input).await },
    )
    .await
}

/// Get target handler.
pub async fn get_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id| async move { service.get_target(&session, &id).await },
        TargetResponse::from,
    )
    .await
}

/// Update target handler.
pub async fn update_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyTargetInput, ModifyTargetRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move { service.modify_target(&session, &id, input).await },
        TargetResponse::from,
    )
    .await
}

/// Delete target handler.
pub async fn delete_target(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, id, ultimate| async move {
            service.delete_target(&session, &id, ultimate).await
        },
    )
    .await
}

/// Build the GMP inline filter string.
pub fn build_gmp_filter(
    filter_string: Option<String>,
    _filter_id: Option<String>,
) -> Option<String> {
    filter_string.filter(|value| !value.trim().is_empty())
}

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/targets`.
pub(crate) fn list_targets_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTargets")
        .tag("Targets")
        .summary("List targets")
        .description("Returns a paginated list of targets.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<TargetListResponse>, _>(ok_json("Paginated list of targets"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/targets`.
pub(crate) fn create_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTarget")
        .tag("Targets")
        .summary("Create a target")
        .description("Creates a new scan target.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTargetDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Target created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/targets/{id}`.
pub(crate) fn get_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTarget")
        .tag("Targets")
        .summary("Get a target")
        .description("Returns the details for a single target.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TargetResponse>, _>(ok_json("Target details"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/targets/{id}`.
pub(crate) fn update_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTarget")
        .tag("Targets")
        .summary("Modify a target")
        .description("Updates an existing target.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTargetDoc>)>()
        .response_with::<200, Json<TargetResponse>, _>(ok_json("Target updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/targets/{id}`.
pub(crate) fn delete_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTarget")
        .tag("Targets")
        .summary("Delete a target")
        .description("Deletes a target. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Target deleted"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "targets_test.rs"]
mod targets_test;
