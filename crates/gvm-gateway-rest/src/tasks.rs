// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task DTOs, request parsing, handlers, and response mapping for the REST adapter.

use std::collections::HashMap;

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
        created_resource_location, parse_uuid, PaginationResponse, ResourceCreatedResponse,
        ResourceRefResponse,
    },
    error::RestError,
    open_enum::open_string_enum,
    openapi::{
        ok_json, problem_response, CreateTaskDoc, ModifyTaskDoc, ResourceIdPathDoc,
        TaskListQueryDoc,
    },
    query::parse_collection_query,
    router::bearer_token,
};

// Re-export domain types used by tests and other modules.
pub use gvm_gateway_domain::{
    CreateTaskInput, ModifyTaskInput, Task, TaskAction, TaskPage, TaskQuery,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_string_enum! {
    /// Hosts ordering strategy.
    pub(crate) enum HostsOrdering {
        Sequential => "sequential",
        Random => "random",
        Reverse => "reverse",
    }
}

open_string_enum! {
    /// Task lifecycle status.
    pub(crate) enum TaskStatus {
        New => "New",
        Requested => "Requested",
        Queued => "Queued",
        Running => "Running",
        StopRequested => "Stop Requested",
        Stopping => "Stopping",
        Processing => "Processing",
        Done => "Done",
        Stopped => "Stopped",
        Error => "Error",
        DeleteRequested => "Delete Requested",
        UltimateDeleteRequested => "Ultimate Delete Requested",
        Container => "Container",
        Interrupted => "Interrupted",
    }
}

/// Observer principals returned for a task.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
#[schemars(rename = "TaskObservers")]
pub(crate) struct TaskObserversResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    users: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<ResourceRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<ResourceRefResponse>,
}

impl TaskObserversResponse {
    fn is_empty(&self) -> bool {
        self.users.is_empty() && self.groups.is_empty() && self.roles.is_empty()
    }
}

impl From<gvm_gateway_domain::TaskObservers> for TaskObserversResponse {
    fn from(observers: gvm_gateway_domain::TaskObservers) -> Self {
        Self {
            users: observers.users,
            groups: observers
                .groups
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            roles: observers
                .roles
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
        }
    }
}

/// JSON body returned for a single task.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Task")]
pub(crate) struct TaskResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<ResourceRefResponse>,
    #[serde(rename = "scanConfig", skip_serializing_if = "Option::is_none")]
    scan_config: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner: Option<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule: Option<ResourceRefResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alerts: Vec<ResourceRefResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alterable: Option<bool>,
    #[serde(rename = "hostsOrdering", skip_serializing_if = "Option::is_none")]
    hosts_ordering: Option<HostsOrdering>,
    #[serde(skip_serializing_if = "TaskObserversResponse::is_empty")]
    observers: TaskObserversResponse,
    #[serde(rename = "schedulePeriods", skip_serializing_if = "Option::is_none")]
    schedule_periods: Option<u32>,
    #[serde(rename = "lastReport", skip_serializing_if = "Option::is_none")]
    last_report: Option<ResourceRefResponse>,
    #[serde(rename = "currentReport", skip_serializing_if = "Option::is_none")]
    current_report: Option<ResourceRefResponse>,
    #[serde(rename = "reportCount", skip_serializing_if = "Option::is_none")]
    report_count: Option<u32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::Task> for TaskResponse {
    fn from(t: gvm_gateway_domain::Task) -> Self {
        Self {
            id: parse_uuid(&t.id),
            name: t.name,
            comment: t.comment,
            status: TaskStatus::parse(&t.status),
            progress: t.progress,
            target: t.target.map(ResourceRefResponse::from),
            scan_config: t.scan_config.map(ResourceRefResponse::from),
            scanner: t.scanner.map(ResourceRefResponse::from),
            schedule: t.schedule.map(ResourceRefResponse::from),
            alerts: t
                .alerts
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            alterable: t.alterable,
            hosts_ordering: t.hosts_ordering.as_deref().map(HostsOrdering::parse),
            observers: TaskObserversResponse::from(t.observers),
            schedule_periods: t.schedule_periods,
            last_report: t.last_report.map(ResourceRefResponse::from),
            current_report: t.current_report.map(ResourceRefResponse::from),
            report_count: t.report_count,
            in_use: t.in_use,
            writable: t.writable,
        }
    }
}

/// JSON body returned for a paginated list of tasks.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TaskList")]
pub(crate) struct TaskListResponse {
    data: Vec<TaskResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::TaskPage> for TaskListResponse {
    fn from(page: gvm_gateway_domain::TaskPage) -> Self {
        Self {
            data: page.data.into_iter().map(TaskResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// JSON body returned for a task start/resume action.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TaskAction")]
pub(crate) struct TaskActionResponse {
    #[serde(rename = "reportId")]
    report_id: Uuid,
}

impl From<gvm_gateway_domain::TaskAction> for TaskActionResponse {
    fn from(a: gvm_gateway_domain::TaskAction) -> Self {
        Self {
            report_id: parse_uuid(&a.report_id),
        }
    }
}

/// Parsed list-tasks query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl TaskListQuery {
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

/// Create-task request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CreateTaskRequest {
    /// Task name (required).
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Target identifier (required).
    #[serde(rename = "targetId")]
    pub target_id: Option<String>,
    /// Scan config identifier (required).
    #[serde(rename = "scanConfigId")]
    pub scan_config_id: Option<String>,
    /// Scanner identifier (required).
    #[serde(rename = "scannerId")]
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    #[serde(rename = "scheduleId")]
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    #[serde(rename = "alertIds", default)]
    pub alert_ids: Vec<String>,
    /// Optional alterable flag.
    pub alterable: Option<bool>,
    /// Optional hosts ordering.
    #[serde(rename = "hostsOrdering")]
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    #[serde(default)]
    pub observers: Vec<String>,
    /// Optional schedule periods.
    #[serde(rename = "schedulePeriods")]
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences. Omitted or empty objects leave preferences unchanged.
    #[serde(default)]
    pub preferences: HashMap<String, String>,
}

impl CreateTaskRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateTaskInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        let target_id = self
            .target_id
            .ok_or_else(|| GatewayError::InvalidInput("targetId is required".to_string()))?;
        validate_uuid("targetId", &target_id)?;
        let scan_config_id = self
            .scan_config_id
            .ok_or_else(|| GatewayError::InvalidInput("scanConfigId is required".to_string()))?;
        validate_uuid("scanConfigId", &scan_config_id)?;
        let scanner_id = self
            .scanner_id
            .ok_or_else(|| GatewayError::InvalidInput("scannerId is required".to_string()))?;
        validate_uuid("scannerId", &scanner_id)?;
        validate_optional_uuid("scheduleId", self.schedule_id.as_deref())?;
        for (index, alert_id) in self.alert_ids.iter().enumerate() {
            validate_uuid(&format!("alertIds[{index}]"), alert_id)?;
        }

        Ok(CreateTaskInput {
            name,
            comment: self.comment,
            target_id,
            scan_config_id,
            scanner_id,
            schedule_id: self.schedule_id,
            alert_ids: self.alert_ids,
            alterable: self.alterable,
            hosts_ordering: self.hosts_ordering,
            observers: self.observers,
            schedule_periods: self.schedule_periods,
            preferences: self.preferences.into_iter().collect(),
        })
    }
}

/// Modify-task request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModifyTaskRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional target identifier.
    #[serde(rename = "targetId")]
    pub target_id: Option<String>,
    /// Optional scan config identifier.
    #[serde(rename = "scanConfigId")]
    pub scan_config_id: Option<String>,
    /// Optional scanner identifier.
    #[serde(rename = "scannerId")]
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    #[serde(rename = "scheduleId")]
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    #[serde(rename = "alertIds")]
    pub alert_ids: Option<Vec<String>>,
    /// Optional hosts ordering.
    #[serde(rename = "hostsOrdering")]
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    #[serde(default)]
    pub observers: Vec<String>,
    /// Optional schedule periods.
    #[serde(rename = "schedulePeriods")]
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences.
    #[serde(default)]
    pub preferences: HashMap<String, String>,
}

impl ModifyTaskRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyTaskInput, GatewayError> {
        validate_optional_uuid("targetId", self.target_id.as_deref())?;
        validate_optional_uuid("scanConfigId", self.scan_config_id.as_deref())?;
        validate_optional_uuid("scannerId", self.scanner_id.as_deref())?;
        validate_optional_uuid("scheduleId", self.schedule_id.as_deref())?;
        if let Some(ref alert_ids) = self.alert_ids {
            for (index, alert_id) in alert_ids.iter().enumerate() {
                validate_uuid(&format!("alertIds[{index}]"), alert_id)?;
            }
        }

        Ok(ModifyTaskInput {
            name: self.name,
            comment: self.comment,
            target_id: self.target_id,
            scan_config_id: self.scan_config_id,
            scanner_id: self.scanner_id,
            schedule_id: self.schedule_id,
            alert_ids: self.alert_ids,
            hosts_ordering: self.hosts_ordering,
            observers: self.observers,
            schedule_periods: self.schedule_periods,
            preferences: self.preferences.into_iter().collect(),
        })
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// List tasks handler.
pub async fn list_tasks(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match TaskListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_tasks(
            &session,
            TaskQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(tasks) => (StatusCode::OK, Json(TaskListResponse::from(tasks))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Create task handler.
pub async fn create_task(
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
    let request = match serde_json::from_slice::<CreateTaskRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response();
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.create_task(&session, input).await {
        Ok(id) => {
            let location = created_resource_location(&instance, &id);
            (
                StatusCode::CREATED,
                [(header::LOCATION, location)],
                Json(ResourceCreatedResponse {
                    id: parse_uuid(&id),
                }),
            )
                .into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get task handler.
pub async fn get_task(
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

    match service.get_task(&session, &id).await {
        Ok(task) => (StatusCode::OK, Json(TaskResponse::from(task))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Update task handler.
pub async fn update_task(
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
    let request = match serde_json::from_slice::<ModifyTaskRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response();
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.modify_task(&session, &id, input).await {
        Ok(task) => (StatusCode::OK, Json(TaskResponse::from(task))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Delete task handler.
pub async fn delete_task(
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

    match service.delete_task(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Start task handler.
pub async fn start_task(
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

    match service.start_task(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Stop task handler.
pub async fn stop_task(
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

    match service.stop_task(&session, &id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Resume task handler.
pub async fn resume_task(
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

    match service.resume_task(&session, &id).await {
        Ok(action) => (StatusCode::OK, Json(TaskActionResponse::from(action))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

/// Validate a UUID-like REST resource identifier.
pub fn validate_uuid(field: &str, value: &str) -> Result<(), GatewayError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| GatewayError::InvalidInput(format!("{field} must be a valid UUID")))
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/tasks`.
pub(crate) fn list_tasks_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTasks")
        .tag("Tasks")
        .summary("List tasks")
        .description("Returns a paginated list of tasks.")
        .security_requirement("bearerAuth")
        .input::<Query<TaskListQueryDoc>>()
        .response_with::<200, Json<TaskListResponse>, _>(ok_json("Paginated list of tasks"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/tasks`.
pub(crate) fn create_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTask")
        .tag("Tasks")
        .summary("Create a task")
        .description("Creates a new scan task.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTaskDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Task created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/tasks/{id}`.
pub(crate) fn get_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTask")
        .tag("Tasks")
        .summary("Get a task")
        .description("Returns the details for a single task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/tasks/{id}`.
pub(crate) fn update_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTask")
        .tag("Tasks")
        .summary("Modify a task")
        .description("Updates an existing task.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTaskDoc>)>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/tasks/{id}`.
pub(crate) fn delete_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTask")
        .tag("Tasks")
        .summary("Delete a task")
        .description("Deletes an existing task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Task deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/start`.
pub(crate) fn start_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("startTask")
        .tag("Tasks")
        .summary("Start a task")
        .description("Starts a scan task. Returns the report identifier created by the action.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task started"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource state conflict");
    problem_response::<504>(op, "Backend service did not respond in time")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/stop`.
pub(crate) fn stop_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("stopTask")
        .tag("Tasks")
        .summary("Stop a running task")
        .description("Stops a currently running scan task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, (), _>(|response| response.description("Task stopped"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/resume`.
pub(crate) fn resume_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("resumeTask")
        .tag("Tasks")
        .summary("Resume a stopped task")
        .description("Resumes a stopped scan task. Returns the report identifier.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task resumed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::TaskResponse;
    use gvm_gateway_domain::{ResourceRef, Task, TaskObservers};

    fn task_with_status(status: &str) -> Task {
        Task {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "Example".to_string(),
            comment: None,
            status: status.to_string(),
            progress: Some(42),
            target: None,
            scan_config: None,
            scanner: None,
            schedule: None,
            alerts: vec![],
            alterable: None,
            hosts_ordering: None,
            observers: TaskObservers::default(),
            schedule_periods: None,
            last_report: None,
            current_report: None,
            report_count: Some(3),
            in_use: false,
            writable: true,
        }
    }

    #[test]
    fn task_response_preserves_unknown_hosts_ordering() {
        let response = TaskResponse::from(Task {
            hosts_ordering: Some("by-latency".to_string()),
            ..task_with_status("Running")
        });

        let value = serde_json::to_value(response).expect("task response should serialize");
        assert_eq!(value["hostsOrdering"], json!("by-latency"));
    }

    #[test]
    fn task_response_preserves_live_gvmd_status_values() {
        // Live task lifecycle values must remain visible to clients rather
        // than being coerced to an older enum variant.
        for status in [
            "New",
            "Requested",
            "Queued",
            "Running",
            "Stop Requested",
            "Stopping",
            "Processing",
            "Done",
            "Stopped",
            "Error",
            "Delete Requested",
            "Ultimate Delete Requested",
            "Container",
            "Interrupted",
        ] {
            let json = serde_json::to_value(TaskResponse::from(task_with_status(status))).unwrap();

            assert_eq!(json["status"], status);
        }
    }

    #[test]
    fn task_response_preserves_unknown_status_and_report_count_semantics() {
        // Unknown future gvmd statuses should still be round-tripped, and the
        // count field must be named for the report-count source data.
        let json =
            serde_json::to_value(TaskResponse::from(task_with_status("Future State"))).unwrap();

        assert_eq!(json["status"], "Future State");
        assert_eq!(json["progress"], 42);
        assert_eq!(json["reportCount"], 3);
        assert!(json.get("resultCount").is_none());
    }

    #[test]
    fn task_response_preserves_group_and_role_observers() {
        // Task observers can be non-user principals; those must not disappear
        // when gvmd reports a group-only or role-only observer shape.
        let response = TaskResponse::from(Task {
            observers: TaskObservers {
                users: vec![],
                groups: vec![ResourceRef {
                    id: "11111111-1111-1111-1111-111111111111".to_string(),
                    name: Some("Auditors".to_string()),
                }],
                roles: vec![ResourceRef {
                    id: "22222222-2222-2222-2222-222222222222".to_string(),
                    name: Some("Observers".to_string()),
                }],
            },
            ..task_with_status("Running")
        });

        let json = serde_json::to_value(response).unwrap();

        assert!(json["observers"].get("users").is_none());
        assert_eq!(json["observers"]["groups"][0]["name"], "Auditors");
        assert_eq!(json["observers"]["roles"][0]["name"], "Observers");
    }
}
