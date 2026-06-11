// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use std::fmt;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{hide_optional_value, GatewayError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{created_resource_location, parse_uuid, PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    router::bearer_token,
    targets::{validate_uuid, TargetListQuery},
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
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match TargetListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service
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
    {
        Ok(credentials) => (
            StatusCode::OK,
            Json(CredentialListResponse::from(credentials)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn list_credential_stores(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.list_credential_stores(&session).await {
        Ok(stores) => (
            StatusCode::OK,
            Json(CredentialStoreListResponse {
                data: stores
                    .into_iter()
                    .map(CredentialStoreResponse::from)
                    .collect(),
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn create_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let request = match serde_json::from_slice::<CreateCredentialRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(credential_json_body_error(error), instance)
                .into_response()
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.create_credential(&session, input).await {
        Ok(id) => (
            StatusCode::CREATED,
            [(header::LOCATION, created_resource_location(&instance, &id))],
            Json(ResourceCreatedResponse {
                id: parse_uuid(&id),
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn get_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.get_credential(&session, &id).await {
        Ok(credential) => {
            (StatusCode::OK, Json(CredentialResponse::from(credential))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn update_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let request = match serde_json::from_slice::<ModifyCredentialRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(credential_json_body_error(error), instance)
                .into_response()
        }
    };
    match service
        .modify_credential(&session, &id, request.validate())
        .await
    {
        Ok(credential) => {
            (StatusCode::OK, Json(CredentialResponse::from(credential))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn delete_credential(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.delete_credential(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
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
        .description("Deletes an existing credential.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Credential deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        credential_json_body_error, CreateCredentialRequest, CredentialResponse, CredentialType,
        ModifyCredentialRequest,
    };
    use gvm_gateway_domain::{Credential, GatewayError};

    fn credential_with_type(credential_type: &str) -> Credential {
        Credential {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "Credential".to_string(),
            comment: None,
            credential_type: Some(credential_type.to_string()),
            login: Some("user".to_string()),
            in_use: false,
            writable: true,
        }
    }

    #[test]
    fn credential_type_deserialization_preserves_unknown_values() {
        // Backend-added credential types must survive deserialization instead
        // of being rejected by the open-enum wrapper.
        let parsed: CredentialType =
            serde_json::from_value(json!("future_credential")).expect("type should parse");

        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            json!("future_credential")
        );
    }

    #[test]
    fn credential_response_preserves_known_and_unknown_types() {
        // Response conversion should expose both known rust-gvm type values and
        // future backend values without collapsing the public `type` field.
        let known = serde_json::to_value(CredentialResponse::from(credential_with_type("up")))
            .expect("credential response should serialize");
        let unknown = serde_json::to_value(CredentialResponse::from(credential_with_type(
            "future_credential",
        )))
        .expect("credential response should serialize");

        assert_eq!(known["type"], json!("up"));
        assert_eq!(unknown["type"], json!("future_credential"));
    }

    #[test]
    fn credential_request_debug_redacts_secrets() {
        // Request DTOs carry write-only credential secrets; debug output must
        // only expose their presence, never their submitted values.
        let create = CreateCredentialRequest {
            name: "Credential".to_string(),
            comment: Some("visible comment".to_string()),
            credential_type: "snmpv3".to_string(),
            login: Some("visible-login".to_string()),
            password: Some("create-password-secret".to_string()),
            private_key: Some("create-private-key-secret".to_string()),
            certificate: Some("public-certificate".to_string()),
            community: Some("create-community-secret".to_string()),
            auth_algorithm: Some("sha1".to_string()),
            privacy_algorithm: Some("aes".to_string()),
            privacy_password: Some("create-privacy-secret".to_string()),
        };
        let modify = ModifyCredentialRequest {
            name: Some("Credential".to_string()),
            comment: Some("visible comment".to_string()),
            login: Some("visible-login".to_string()),
            password: Some("modify-password-secret".to_string()),
            private_key: Some("modify-private-key-secret".to_string()),
            certificate: Some("public-certificate".to_string()),
            community: Some("modify-community-secret".to_string()),
            auth_algorithm: Some("sha1".to_string()),
            privacy_algorithm: Some("aes".to_string()),
            privacy_password: Some("modify-privacy-secret".to_string()),
        };

        let debug = format!("{create:?}\n{modify:?}");

        assert!(debug.contains("visible-login"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("create-password-secret"));
        assert!(!debug.contains("create-private-key-secret"));
        assert!(!debug.contains("create-community-secret"));
        assert!(!debug.contains("create-privacy-secret"));
        assert!(!debug.contains("modify-password-secret"));
        assert!(!debug.contains("modify-private-key-secret"));
        assert!(!debug.contains("modify-community-secret"));
        assert!(!debug.contains("modify-privacy-secret"));
    }

    #[test]
    fn credential_json_parse_error_detail_omits_submitted_values() {
        // Credential parse failures become client-visible problem details, so
        // the detail string must not reuse serde's value-bearing error text.
        let error = serde_json::from_value::<CreateCredentialRequest>(json!({
            "name": "Credential",
            "type": "up",
            "password": 123456789,
            "privateKey": 987654321,
            "community": 111222333,
            "privacyPassword": 444555666
        }))
        .expect_err("numeric secret fields should fail string deserialization");

        let GatewayError::InvalidInput(detail) = credential_json_body_error(error) else {
            panic!("credential parse errors should map to invalid input");
        };

        assert!(detail.starts_with("invalid JSON body at line "));
        assert!(!detail.contains("123456789"));
        assert!(!detail.contains("987654321"));
        assert!(!detail.contains("111222333"));
        assert!(!detail.contains("444555666"));
    }
}
