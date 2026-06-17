// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port-list DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

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

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceCreatedResponse},
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{CollectionListQuery, DeleteResourceQueryParams},
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

impl ValidateInto<CreatePortListInput> for CreatePortListRequest {
    fn validate_into(self) -> Result<CreatePortListInput, GatewayError> {
        self.validate()
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

impl ValidateInto<ModifyPortListInput> for ModifyPortListRequest {
    fn validate_into(self) -> Result<ModifyPortListInput, GatewayError> {
        Ok(self.validate())
    }
}

pub async fn list_port_lists(
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
        },
        PortListListResponse::from,
    )
    .await
}

pub async fn create_port_list(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreatePortListInput, CreatePortListRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_port_list(&session, input).await },
    )
    .await
}

pub async fn get_port_list(
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
        |service, session, id| async move { service.get_port_list(&session, &id).await },
        PortListResponse::from,
    )
    .await
}

pub async fn update_port_list(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyPortListInput, ModifyPortListRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_port_list(&session, &id, input).await
        },
        PortListResponse::from,
    )
    .await
}

pub async fn delete_port_list(
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
            service.delete_port_list(&session, &id, ultimate).await
        },
    )
    .await
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
        .description("Deletes a port list. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Port list deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
