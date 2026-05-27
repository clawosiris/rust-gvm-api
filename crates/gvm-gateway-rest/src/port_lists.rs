// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port-list DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{created_resource_location, parse_uuid, PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    router::bearer_token,
    targets::{validate_uuid, TargetListQuery},
};

pub use gvm_gateway_domain::{
    CreatePortListInput, ModifyPortListInput, PortList, PortListPage, PortListQuery,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "PortList")]
pub(crate) struct PortListResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "portCount", skip_serializing_if = "Option::is_none")]
    port_count: Option<u32>,
    #[serde(rename = "tcpCount", skip_serializing_if = "Option::is_none")]
    tcp_count: Option<u32>,
    #[serde(rename = "udpCount", skip_serializing_if = "Option::is_none")]
    udp_count: Option<u32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<PortList> for PortListResponse {
    fn from(port_list: PortList) -> Self {
        Self {
            id: parse_uuid(&port_list.id),
            name: port_list.name,
            comment: port_list.comment,
            port_count: port_list.port_count,
            tcp_count: port_list.tcp_count,
            udp_count: port_list.udp_count,
            in_use: port_list.in_use,
            writable: port_list.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "PortListList")]
pub(crate) struct PortListListResponse {
    data: Vec<PortListResponse>,
    pagination: PaginationResponse,
}

impl From<PortListPage> for PortListListResponse {
    fn from(page: PortListPage) -> Self {
        Self {
            data: page.data.into_iter().map(PortListResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "CreatePortList")]
pub struct CreatePortListRequest {
    pub name: String,
    pub comment: Option<String>,
    #[serde(rename = "portRange")]
    pub port_range: Option<String>,
}

impl CreatePortListRequest {
    fn validate(self) -> Result<CreatePortListInput, GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::InvalidInput("name is required".to_string()));
        }
        Ok(CreatePortListInput {
            name: self.name,
            comment: self.comment,
            port_range: self.port_range,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifyPortList")]
pub struct ModifyPortListRequest {
    pub comment: Option<String>,
    #[serde(rename = "portRange")]
    pub port_range: Option<String>,
}

impl ModifyPortListRequest {
    fn validate(self) -> ModifyPortListInput {
        ModifyPortListInput {
            comment: self.comment,
            port_range: self.port_range,
        }
    }
}

pub async fn list_port_lists(
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
        .list_port_lists(
            &session,
            PortListQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(port_lists) => {
            (StatusCode::OK, Json(PortListListResponse::from(port_lists))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn create_port_list(
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
    let request = match serde_json::from_slice::<CreatePortListRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response()
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.create_port_list(&session, input).await {
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

pub async fn get_port_list(
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
    match service.get_port_list(&session, &id).await {
        Ok(port_list) => (StatusCode::OK, Json(PortListResponse::from(port_list))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn update_port_list(
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
    let request = match serde_json::from_slice::<ModifyPortListRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response()
        }
    };
    match service
        .modify_port_list(&session, &id, request.validate())
        .await
    {
        Ok(port_list) => (StatusCode::OK, Json(PortListResponse::from(port_list))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn delete_port_list(
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
    match service.delete_port_list(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_port_lists_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getPortLists")
        .tag("Port Lists")
        .summary("List port lists")
        .description("Returns a paginated list of port lists.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<PortListListResponse>, _>(ok_json(
            "Paginated list of port lists",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn create_port_list_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createPortList")
        .tag("Port Lists")
        .summary("Create a port list")
        .description("Creates a new port list.")
        .security_requirement("bearerAuth")
        .input::<Json<CreatePortListRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Port list created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_port_list_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getPortList")
        .tag("Port Lists")
        .summary("Get a port list")
        .description("Returns a single port list.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<PortListResponse>, _>(ok_json("Port list details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_port_list_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyPortList")
        .tag("Port Lists")
        .summary("Modify a port list")
        .description("Updates an existing port list.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyPortListRequest>)>()
        .response_with::<200, Json<PortListResponse>, _>(ok_json("Port list updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_port_list_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deletePortList")
        .tag("Port Lists")
        .summary("Delete a port list")
        .description("Deletes an existing port list.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Port list deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
