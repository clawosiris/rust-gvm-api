// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Schedule DTOs and handlers for the REST adapter.

#![allow(missing_docs)]

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{datetime_schema, parse_uuid, PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    openapi::{ok_json, problem_response, ResourceIdPathDoc, TargetListQueryDoc},
    query::{CollectionListQuery, DeleteResourceQueryParams},
    router::bearer_token,
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

impl ValidateInto<CreateScheduleInput> for CreateScheduleRequest {
    fn validate_into(self) -> Result<CreateScheduleInput, GatewayError> {
        self.validate()
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

impl ValidateInto<ModifyScheduleInput> for ModifyScheduleRequest {
    fn validate_into(self) -> Result<ModifyScheduleInput, GatewayError> {
        Ok(self.validate())
    }
}

pub async fn list_schedules(
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
        },
        ScheduleListResponse::from,
    )
    .await
}

pub async fn create_schedule(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateScheduleInput, CreateScheduleRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_schedule(&session, input).await },
    )
    .await
}

pub async fn get_schedule(
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
        |service, session, id| async move { service.get_schedule(&session, &id).await },
        ScheduleResponse::from,
    )
    .await
}

pub async fn update_schedule(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyScheduleInput, ModifyScheduleRequest, _, _, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, id, input| async move {
            service.modify_schedule(&session, &id, input).await
        },
        ScheduleResponse::from,
    )
    .await
}

pub async fn delete_schedule(
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
            service.delete_schedule(&session, &id, ultimate).await
        },
    )
    .await
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
