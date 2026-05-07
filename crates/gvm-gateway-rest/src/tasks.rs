// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task DTOs, request parsing, handlers, and response mapping for the REST adapter.

use std::collections::HashMap;

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;
use uuid::Uuid;

use crate::{error::RestError, router::bearer_token};

// Re-export domain types used by tests and other modules.
pub use gvm_gateway_domain::{
    CreateTaskInput, ModifyTaskInput, Task, TaskAction, TaskPage, TaskQuery,
};

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
        let mut filter_string = None;
        let mut filter_id = None;
        let mut page = None;
        let mut per_page = None;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                "filter" => filter_string = Some(value.to_string()),
                "filterId" => {
                    validate_uuid("filterId", value)?;
                    filter_id = Some(value.to_string());
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
    /// Optional key-value scan preferences.
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
        Ok(tasks) => (StatusCode::OK, Json(tasks)).into_response(),
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
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
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
        Ok(task) => (StatusCode::OK, Json(task)).into_response(),
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
        Ok(task) => (StatusCode::OK, Json(task)).into_response(),
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
        Ok(action) => (StatusCode::OK, Json(action)).into_response(),
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
        Ok(action) => (StatusCode::OK, Json(action)).into_response(),
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
