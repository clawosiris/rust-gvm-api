// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report-format, filter, tag, and ticket DTOs plus REST handlers.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{GatewayError, SupportingResourceQuery};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse, ResourceRefResponse},
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc},
    results::NvtRefResponse,
    router::bearer_token,
    targets::validate_uuid,
};

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct SupportingResourceListQueryParams {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

/// Normalized query parameters for supporting-resource list endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportingListQuery {
    /// Optional raw GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// One-based page number.
    pub page: u32,
    /// Requested page size, clamped server-side.
    pub per_page: u32,
}

impl SupportingListQuery {
    /// Parses a raw query string into a normalized supporting-resource query.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut filter_string = None;
        let mut filter_id = None;
        let mut page = None;
        let mut per_page = None;

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "filter" => filter_string = Some(value.into_owned()),
                "filterId" => {
                    validate_uuid("filterId", value.as_ref())?;
                    filter_id = Some(value.into_owned());
                }
                "page" => {
                    page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("page must be a positive integer".to_string())
                    })?);
                }
                "perPage" | "per_page" => {
                    per_page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                    })?);
                }
                _ => {}
            }
        }

        let page = page.unwrap_or(1);
        if page == 0 {
            return Err(GatewayError::InvalidInput(
                "page must be greater than or equal to 1".to_string(),
            ));
        }
        let per_page = per_page.unwrap_or(25).clamp(1, 1000);

        Ok(Self {
            filter_string,
            filter_id,
            page,
            per_page,
        })
    }
}

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "SupportingResourceMeta")]
pub(crate) struct SupportingResourceMetaResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
}

impl From<gvm_gateway_domain::SupportingResourceMeta> for SupportingResourceMetaResponse {
    fn from(meta: gvm_gateway_domain::SupportingResourceMeta) -> Self {
        Self {
            id: parse_uuid(&meta.id),
            name: meta.name,
            comment: meta.comment,
            creation_time: meta.creation_time,
            modification_time: meta.modification_time,
            writable: meta.writable,
            in_use: meta.in_use,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportFormat")]
pub(crate) struct ReportFormatResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<String>,
    active: bool,
    predefined: bool,
}

impl From<gvm_gateway_domain::ReportFormat> for ReportFormatResponse {
    fn from(report_format: gvm_gateway_domain::ReportFormat) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(report_format.meta),
            content_type: report_format.content_type,
            extension: report_format.extension,
            summary: report_format.summary,
            trust: report_format.trust,
            active: report_format.active,
            predefined: report_format.predefined,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportFormatList")]
pub(crate) struct ReportFormatListResponse {
    data: Vec<ReportFormatResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ReportFormatPage> for ReportFormatListResponse {
    fn from(page: gvm_gateway_domain::ReportFormatPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ReportFormatResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Filter")]
pub(crate) struct FilterResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    filter_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    term: Option<String>,
}

impl From<gvm_gateway_domain::Filter> for FilterResponse {
    fn from(filter: gvm_gateway_domain::Filter) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(filter.meta),
            filter_type: filter.filter_type,
            term: filter.term,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "FilterList")]
pub(crate) struct FilterListResponse {
    data: Vec<FilterResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::FilterPage> for FilterListResponse {
    fn from(page: gvm_gateway_domain::FilterPage) -> Self {
        Self {
            data: page.data.into_iter().map(FilterResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagResource")]
pub(crate) struct TagResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(rename = "resourceCount", skip_serializing_if = "Option::is_none")]
    resource_count: Option<u32>,
    active: bool,
}

impl From<gvm_gateway_domain::Tag> for TagResponse {
    fn from(tag: gvm_gateway_domain::Tag) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(tag.meta),
            value: tag.value,
            resource_type: tag.resource_type,
            resource_count: tag.resource_count,
            active: tag.active,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TagList")]
pub(crate) struct TagListResponse {
    data: Vec<TagResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TagPage> for TagListResponse {
    fn from(page: gvm_gateway_domain::TagPage) -> Self {
        Self {
            data: page.data.into_iter().map(TagResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Ticket")]
pub(crate) struct TicketResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(rename = "assignedTo", skip_serializing_if = "Option::is_none")]
    assigned_to: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(rename = "openNote", skip_serializing_if = "Option::is_none")]
    open_note: Option<String>,
    #[serde(rename = "fixedNote", skip_serializing_if = "Option::is_none")]
    fixed_note: Option<String>,
    #[serde(rename = "closedNote", skip_serializing_if = "Option::is_none")]
    closed_note: Option<String>,
}

impl From<gvm_gateway_domain::Ticket> for TicketResponse {
    fn from(ticket: gvm_gateway_domain::Ticket) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(ticket.meta),
            status: ticket.status,
            assigned_to: ticket.assigned_to.map(ResourceRefResponse::from),
            result: ticket.result.map(ResourceRefResponse::from),
            task: ticket.task.map(ResourceRefResponse::from),
            open_note: ticket.open_note,
            fixed_note: ticket.fixed_note,
            closed_note: ticket.closed_note,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TicketList")]
pub(crate) struct TicketListResponse {
    data: Vec<TicketResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TicketPage> for TicketListResponse {
    fn from(page: gvm_gateway_domain::TicketPage) -> Self {
        Self {
            data: page.data.into_iter().map(TicketResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Note")]
pub(crate) struct NoteResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Note> for NoteResponse {
    fn from(note: gvm_gateway_domain::Note) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(note.meta),
            text: note.text,
            nvt: note.nvt.map(NvtRefResponse::from),
            hosts: note.hosts,
            port: note.port,
            severity: note.severity,
            task: note.task.map(ResourceRefResponse::from),
            result: note.result.map(ResourceRefResponse::from),
            active: note.active,
            end_time: note.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "NoteList")]
pub(crate) struct NoteListResponse {
    data: Vec<NoteResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::NotePage> for NoteListResponse {
    fn from(page: gvm_gateway_domain::NotePage) -> Self {
        Self {
            data: page.data.into_iter().map(NoteResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Override")]
pub(crate) struct OverrideResponse {
    #[serde(flatten)]
    meta: SupportingResourceMetaResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvt: Option<NvtRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(rename = "newSeverity", skip_serializing_if = "Option::is_none")]
    new_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResourceRefResponse>,
    active: bool,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
}

impl From<gvm_gateway_domain::Override> for OverrideResponse {
    fn from(override_: gvm_gateway_domain::Override) -> Self {
        Self {
            meta: SupportingResourceMetaResponse::from(override_.meta),
            text: override_.text,
            nvt: override_.nvt.map(NvtRefResponse::from),
            hosts: override_.hosts,
            port: override_.port,
            severity: override_.severity,
            new_severity: override_.new_severity,
            task: override_.task.map(ResourceRefResponse::from),
            result: override_.result.map(ResourceRefResponse::from),
            active: override_.active,
            end_time: override_.end_time,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "OverrideList")]
pub(crate) struct OverrideListResponse {
    data: Vec<OverrideResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::OverridePage> for OverrideListResponse {
    fn from(page: gvm_gateway_domain::OverridePage) -> Self {
        Self {
            data: page.data.into_iter().map(OverrideResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

fn supporting_query(query: SupportingListQuery) -> SupportingResourceQuery {
    SupportingResourceQuery {
        filter_string: query.filter_string,
        filter_id: query.filter_id,
        page: query.page,
        per_page: query.per_page,
    }
}

/// Lists report formats available to the authenticated session.
pub async fn list_report_formats(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_report_formats(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(ReportFormatListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single report format by id.
pub async fn get_report_format(
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

    match service.get_report_format(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(ReportFormatResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists saved filters visible to the authenticated session.
pub async fn list_filters(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_filters(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(FilterListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single saved filter by id.
pub async fn get_filter(
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

    match service.get_filter(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(FilterResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists tags visible to the authenticated session.
pub async fn list_tags(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.list_tags(&session, supporting_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(TagListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single tag by id.
pub async fn get_tag(
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

    match service.get_tag(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(TagResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists tickets visible to the authenticated session.
pub async fn list_tickets(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_tickets(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(TicketListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single ticket by id.
pub async fn get_ticket(
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

    match service.get_ticket(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(TicketResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists notes visible to the authenticated session.
pub async fn list_notes(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.list_notes(&session, supporting_query(query)).await {
        Ok(page) => (StatusCode::OK, Json(NoteListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single note by id.
pub async fn get_note(
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

    match service.get_note(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(NoteResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Lists overrides visible to the authenticated session.
pub async fn list_overrides(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match SupportingListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_overrides(&session, supporting_query(query))
        .await
    {
        Ok(page) => (StatusCode::OK, Json(OverrideListResponse::from(page))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Returns a single override by id.
pub async fn get_override(
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

    match service.get_override(&session, &id).await {
        Ok(item) => (StatusCode::OK, Json(OverrideResponse::from(item))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_report_formats_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportFormats")
        .tag("Report Formats")
        .summary("List report formats")
        .description("Returns a paginated list of report formats available for report export.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<ReportFormatListResponse>, _>(ok_json(
            "Paginated list of report formats",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_report_format_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportFormat")
        .tag("Report Formats")
        .summary("Get a report format")
        .description("Returns the details for a single report format.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ReportFormatResponse>, _>(ok_json("Report format details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_filters_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilters")
        .tag("Filters")
        .summary("List filters")
        .description("Returns a paginated list of saved filters.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<FilterListResponse>, _>(ok_json(
            "Paginated list of saved filters",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_filter_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getFilter")
        .tag("Filters")
        .summary("Get a filter")
        .description("Returns the details for a single saved filter.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<FilterResponse>, _>(ok_json("Filter details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_tags_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTags")
        .tag("Tags")
        .summary("List tags")
        .description("Returns a paginated list of tags.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<TagListResponse>, _>(ok_json("Paginated list of tags"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_tag_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTag")
        .tag("Tags")
        .summary("Get a tag")
        .description("Returns the details for a single tag.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TagResponse>, _>(ok_json("Tag details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_tickets_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTickets")
        .tag("Tickets")
        .summary("List tickets")
        .description("Returns a paginated list of tickets.")
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<TicketListResponse>, _>(ok_json("Paginated list of tickets"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_ticket_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTicket")
        .tag("Tickets")
        .summary("Get a ticket")
        .description("Returns the details for a single ticket.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TicketResponse>, _>(ok_json("Ticket details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_notes_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNotes")
        .tag("Notes")
        .summary("List notes")
        .description(
            "Returns a paginated list of notes that annotate findings. Filter expressions can scope notes to the related task, result, NVT, host, or port selectors exposed by each note.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<NoteListResponse>, _>(ok_json("Paginated list of notes"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_note_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getNote")
        .tag("Notes")
        .summary("Get a note")
        .description(
            "Returns the details for a single note, including any related task/result identifiers and the NVT/host/port selectors the note annotates.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<NoteResponse>, _>(ok_json("Note details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_overrides_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverrides")
        .tag("Overrides")
        .summary("List overrides")
        .description(
            "Returns a paginated list of overrides that change finding interpretation. Filter expressions can scope overrides to the related task, result, NVT, host, or port selectors exposed by each override.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<SupportingResourceListQueryParams>>()
        .response_with::<200, Json<OverrideListResponse>, _>(ok_json(
            "Paginated list of overrides",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_override_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getOverride")
        .tag("Overrides")
        .summary("Get an override")
        .description(
            "Returns the details for a single override, including any related task/result identifiers, the annotated NVT/host/port selectors, and the replacement severity when one is set.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<OverrideResponse>, _>(ok_json("Override details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
mod tests {
    use super::SupportingListQuery;

    #[test]
    fn supporting_query_decodes_percent_encoded_filter_values() {
        let parsed = SupportingListQuery::try_from_query_string(
            "filter=name~webserver%20and%20severity%3E5&perPage=10&page=2",
        )
        .expect("supporting-resource query should parse");

        assert_eq!(
            parsed.filter_string.as_deref(),
            Some("name~webserver and severity>5")
        );
        assert_eq!(parsed.page, 2);
        assert_eq!(parsed.per_page, 10);
    }

    #[test]
    fn supporting_query_rejects_zero_page_after_decoding() {
        let error = SupportingListQuery::try_from_query_string("page=0")
            .expect_err("page=0 should remain invalid");

        match error {
            gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
                assert_eq!(detail, "page must be greater than or equal to 1");
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }
}
