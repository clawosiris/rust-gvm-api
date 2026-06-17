// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use std::fmt;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{hide_optional_value, GatewayError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    handler::{
        authenticated_resource, create_resource_with_json_error, delete_resource, get_resource,
        list_resource, update_resource_with_json_error, ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{CollectionListQuery, DeleteResourceQueryParams},
};

pub use gvm_gateway_domain::{
    CreateCredentialInput, Credential, CredentialPage, CredentialQuery, CredentialStore,
    ModifyCredentialInput,
};

open_string_enum! {
    /// Credential type code.
    pub(crate) enum CredentialType {
        ClientCertificate => "cc",
        PasswordOnly => "pw",
        SnmpV1Or2c => "snmp",
        SnmpV3 => "snmpv3",
        UsernamePassword => "up",
        UsernameSshKey => "usk",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Credential")]
pub(crate) struct CredentialResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    credential_type: Option<CredentialType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        Self {
            id: parse_uuid(&credential.id),
            name: credential.name,
            comment: credential.comment,
            credential_type: credential
                .credential_type
                .as_deref()
                .map(CredentialType::parse),
            login: credential.login,
            in_use: credential.in_use,
            writable: credential.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialList")]
pub(crate) struct CredentialListResponse {
    data: Vec<CredentialResponse>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialStore")]
pub(crate) struct CredentialStoreResponse {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    default: bool,
    writable: bool,
}

impl From<CredentialStore> for CredentialStoreResponse {
    fn from(store: CredentialStore) -> Self {
        Self {
            id: store.id,
            name: store.name,
            provider: store.provider,
            default: store.default,
            writable: store.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "CredentialStoreList")]
pub(crate) struct CredentialStoreListResponse {
    data: Vec<CredentialStoreResponse>,
}

impl From<Vec<CredentialStore>> for CredentialStoreListResponse {
    fn from(stores: Vec<CredentialStore>) -> Self {
        Self {
            data: stores
                .into_iter()
                .map(CredentialStoreResponse::from)
                .collect(),
        }
    }
}

impl From<CredentialPage> for CredentialListResponse {
    fn from(page: CredentialPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(CredentialResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Deserialize, JsonSchema)]
#[schemars(rename = "CreateCredential")]
pub struct CreateCredentialRequest {
    pub name: String,
    pub comment: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub login: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub community: Option<String>,
    #[serde(rename = "authAlgorithm")]
    pub auth_algorithm: Option<String>,
    #[serde(rename = "privacyAlgorithm")]
    pub privacy_algorithm: Option<String>,
    #[serde(rename = "privacyPassword")]
    pub privacy_password: Option<String>,
}

impl fmt::Debug for CreateCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateCredentialRequest")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("credential_type", &self.credential_type)
            .field("login", &self.login)
            .field("password", &hide_optional_value(&self.password))
            .field("private_key", &hide_optional_value(&self.private_key))
            .field("certificate", &self.certificate)
            .field("community", &hide_optional_value(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field(
                "privacy_password",
                &hide_optional_value(&self.privacy_password),
            )
            .finish()
    }
}

impl CreateCredentialRequest {
    fn validate(self) -> Result<CreateCredentialInput, GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::InvalidInput("name is required".to_string()));
        }
        if self.credential_type.trim().is_empty() {
            return Err(GatewayError::InvalidInput("type is required".to_string()));
        }
        Ok(CreateCredentialInput {
            name: self.name,
            comment: self.comment,
            credential_type: self.credential_type,
            login: self.login,
            password: self.password,
            private_key: self.private_key,
            certificate: self.certificate,
            community: self.community,
            auth_algorithm: self.auth_algorithm,
            privacy_algorithm: self.privacy_algorithm,
            privacy_password: self.privacy_password,
        })
    }
}

impl ValidateInto<CreateCredentialInput> for CreateCredentialRequest {
    fn validate_into(self) -> Result<CreateCredentialInput, GatewayError> {
        self.validate()
    }
}

#[derive(Clone, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyCredential")]
pub struct ModifyCredentialRequest {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    pub community: Option<String>,
    #[serde(rename = "authAlgorithm")]
    pub auth_algorithm: Option<String>,
    #[serde(rename = "privacyAlgorithm")]
    pub privacy_algorithm: Option<String>,
    #[serde(rename = "privacyPassword")]
    pub privacy_password: Option<String>,
}

impl fmt::Debug for ModifyCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyCredentialRequest")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("login", &self.login)
            .field("password", &hide_optional_value(&self.password))
            .field("private_key", &hide_optional_value(&self.private_key))
            .field("certificate", &self.certificate)
            .field("community", &hide_optional_value(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field(
                "privacy_password",
                &hide_optional_value(&self.privacy_password),
            )
            .finish()
    }
}

impl ModifyCredentialRequest {
    fn validate(self) -> ModifyCredentialInput {
        ModifyCredentialInput {
            name: self.name,
            comment: self.comment,
            login: self.login,
            password: self.password,
            private_key: self.private_key,
            certificate: self.certificate,
            community: self.community,
            auth_algorithm: self.auth_algorithm,
            privacy_algorithm: self.privacy_algorithm,
            privacy_password: self.privacy_password,
        }
    }
}

impl ValidateInto<ModifyCredentialInput> for ModifyCredentialRequest {
    fn validate_into(self) -> Result<ModifyCredentialInput, GatewayError> {
        Ok(self.validate())
    }
}

fn credential_json_body_error(error: serde_json::Error) -> GatewayError {
    GatewayError::InvalidInput(format!(
        "invalid JSON body at line {}, column {}",
        error.line(),
        error.column()
    ))
}

pub async fn list_credentials(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        CollectionListQuery::try_from_query_string,
        |service, session, query| async move {
            service
                .list_credentials(
                    &session,
                    CredentialQuery {
                        filter_string: query.filter_string,
                        filter_id: query.filter_id,
                        page: query.page,
                        per_page: query.per_page,
                    },
                )
                .await
        },
        CredentialListResponse::from,
    )
    .await
}

pub async fn list_credential_stores(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    authenticated_resource(
        service,
        headers,
        uri,
        |service, session| async move { service.list_credential_stores(&session).await },
        CredentialStoreListResponse::from,
    )
    .await
}

pub async fn create_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource_with_json_error::<CreateCredentialInput, CreateCredentialRequest, _, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_credential(&session, input).await },
        credential_json_body_error,
    )
    .await
}

pub async fn get_credential(
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
        |service, session, id| async move { service.get_credential(&session, &id).await },
        CredentialResponse::from,
    )
    .await
}

pub async fn update_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource_with_json_error::<
        ModifyCredentialInput,
        ModifyCredentialRequest,
        _,
        _,
        _,
        _,
        _,
    >(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_credential(&session, &id, input).await
        },
        CredentialResponse::from,
        credential_json_body_error,
    )
    .await
}

pub async fn delete_credential(
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
            service.delete_credential(&session, &id, ultimate).await
        },
    )
    .await
}

pub(crate) fn list_credentials_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredentials")
        .tag("Credentials")
        .summary("List credentials")
        .description("Returns a paginated list of credentials.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<CredentialListResponse>, _>(ok_json(
            "Paginated list of credentials",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/credential-stores`.
pub(crate) fn list_credential_stores_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredentialStores")
        .tag("Credentials")
        .summary("List available credential stores")
        .description("Returns backend credential stores available to credential workflows.")
        .security_requirement("bearerAuth")
        .response_with::<200, Json<CredentialStoreListResponse>, _>(ok_json(
            "Available credential stores",
        ));

    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn create_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createCredential")
        .tag("Credentials")
        .summary("Create a credential")
        .description("Creates a new credential.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateCredentialRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Credential created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getCredential")
        .tag("Credentials")
        .summary("Get a credential")
        .description("Returns a single credential.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<CredentialResponse>, _>(ok_json("Credential details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyCredential")
        .tag("Credentials")
        .summary("Modify a credential")
        .description("Updates an existing credential.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyCredentialRequest>)>()
        .response_with::<200, Json<CredentialResponse>, _>(ok_json("Credential updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_credential_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteCredential")
        .tag("Credentials")
        .summary("Delete a credential")
        .description("Deletes a credential. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Credential deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "credentials_test.rs"]
mod credentials_test;
