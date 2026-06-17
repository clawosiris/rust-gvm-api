// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Schedule DTOs and handlers for the REST adapter.

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
    dto::{
        created_resource_location, datetime_schema, parse_uuid, PaginationResponse,
        ResourceCreatedResponse,
    },
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{parse_delete_resource_query, CollectionListQuery, DeleteResourceQueryParams},
    router::bearer_token,
    targets::validate_uuid,
};

pub use gvm_gateway_domain::{
    CreateScheduleInput, ModifyScheduleInput, Schedule, SchedulePage, ScheduleQuery,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Schedule")]
pub(crate) struct ScheduleResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icalendar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<String>,
    #[serde(rename = "firstRun", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    first_run: Option<String>,
    #[serde(rename = "nextRun", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    next_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration: Option<u32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<Schedule> for ScheduleResponse {
    fn from(schedule: Schedule) -> Self {
        Self {
            id: parse_uuid(&schedule.id),
            name: schedule.name,
            comment: schedule.comment,
            icalendar: schedule.icalendar,
            timezone: schedule.timezone,
            first_run: schedule.first_run,
            next_run: schedule.next_run,
            duration: schedule.duration,
            in_use: schedule.in_use,
            writable: schedule.writable,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScheduleList")]
pub(crate) struct ScheduleListResponse {
    data: Vec<ScheduleResponse>,
    pagination: PaginationResponse,
}

impl From<SchedulePage> for ScheduleListResponse {
    fn from(page: SchedulePage) -> Self {
        Self {
            data: page.data.into_iter().map(ScheduleResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(rename = "CreateSchedule")]
pub struct CreateScheduleRequest {
    pub name: String,
    pub comment: Option<String>,
    pub icalendar: String,
    pub timezone: String,
}

impl CreateScheduleRequest {
    fn validate(self) -> Result<CreateScheduleInput, GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::InvalidInput("name is required".to_string()));
        }
        if self.icalendar.trim().is_empty() {
            return Err(GatewayError::InvalidInput(
                "icalendar is required".to_string(),
            ));
        }
        if self.timezone.trim().is_empty() {
            return Err(GatewayError::InvalidInput(
                "timezone is required".to_string(),
            ));
        }
        Ok(CreateScheduleInput {
            name: self.name,
            comment: self.comment,
            icalendar: self.icalendar,
            timezone: self.timezone,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[schemars(rename = "ModifySchedule")]
pub struct ModifyScheduleRequest {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub icalendar: Option<String>,
    pub timezone: Option<String>,
}

impl ModifyScheduleRequest {
    fn validate(self) -> ModifyScheduleInput {
        ModifyScheduleInput {
            name: self.name,
            comment: self.comment,
            icalendar: self.icalendar,
            timezone: self.timezone,
        }
    }
}

pub async fn list_schedules(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match CollectionListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service
        .list_schedules(
            &session,
            ScheduleQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(schedules) => {
            (StatusCode::OK, Json(ScheduleListResponse::from(schedules))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn create_schedule(
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
    let request = match serde_json::from_slice::<CreateScheduleRequest>(&body) {
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
    match service.create_schedule(&session, input).await {
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

pub async fn get_schedule(
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
    match service.get_schedule(&session, &id).await {
        Ok(schedule) => (StatusCode::OK, Json(ScheduleResponse::from(schedule))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn update_schedule(
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
    let request = match serde_json::from_slice::<ModifyScheduleRequest>(&body) {
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
        .modify_schedule(&session, &id, request.validate())
        .await
    {
        Ok(schedule) => (StatusCode::OK, Json(ScheduleResponse::from(schedule))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub async fn delete_schedule(
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
    let ultimate = match parse_delete_resource_query(uri.query().unwrap_or("")) {
        Ok(ultimate) => ultimate,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.delete_schedule(&session, &id, ultimate).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

pub(crate) fn list_schedules_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getSchedules")
        .tag("Schedules")
        .summary("List schedules")
        .description("Returns a paginated list of schedules.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<ScheduleListResponse>, _>(ok_json(
            "Paginated list of schedules",
        ));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn create_schedule_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createSchedule")
        .tag("Schedules")
        .summary("Create a schedule")
        .description("Creates a new schedule.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateScheduleRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Schedule created"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_schedule_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getSchedule")
        .tag("Schedules")
        .summary("Get a schedule")
        .description("Returns a single schedule.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScheduleResponse>, _>(ok_json("Schedule details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_schedule_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifySchedule")
        .tag("Schedules")
        .summary("Modify a schedule")
        .description("Updates an existing schedule.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyScheduleRequest>)>()
        .response_with::<200, Json<ScheduleResponse>, _>(ok_json("Schedule updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_schedule_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteSchedule")
        .tag("Schedules")
        .summary("Delete a schedule")
        .description("Deletes a schedule. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
        .response_with::<204, (), _>(|response| response.description("Schedule deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
