// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan config DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateScanConfigInput, GatewayError, ModifyScanConfigInput, ScanConfigQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{created_resource_location, parse_uuid, PaginationResponse, ResourceCreatedResponse},
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc, ScanConfigListQueryDoc},
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// JSON body returned for a single scan config.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfig")]
pub(crate) struct ScanConfigResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "familyCount", skip_serializing_if = "Option::is_none")]
    family_count: Option<u32>,
    #[serde(rename = "nvtCount", skip_serializing_if = "Option::is_none")]
    nvt_count: Option<u32>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    config_type: Option<u32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::ScanConfig> for ScanConfigResponse {
    fn from(sc: gvm_gateway_domain::ScanConfig) -> Self {
        Self {
            id: parse_uuid(&sc.id),
            name: sc.name,
            comment: sc.comment,
            family_count: sc.family_count,
            nvt_count: sc.nvt_count,
            config_type: sc.config_type,
            in_use: sc.in_use,
            writable: sc.writable,
        }
    }
}

/// JSON body returned for a paginated list of scan configs.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScanConfigList")]
pub(crate) struct ScanConfigListResponse {
    data: Vec<ScanConfigResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ScanConfigPage> for ScanConfigListResponse {
    fn from(page: gvm_gateway_domain::ScanConfigPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(ScanConfigResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-scan-configs query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanConfigListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ScanConfigListQuery {
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

/// Create-scan-config request payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(rename = "CreateScanConfig")]
pub struct CreateScanConfigRequest {
    /// Optional name so validation can return RFC 9457 instead of extractor failures.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional base scan config identifier to copy from.
    #[serde(rename = "baseScanConfigId")]
    #[schemars(with = "Option<Uuid>")]
    pub base_scan_config_id: Option<String>,
}

impl CreateScanConfigRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateScanConfigInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        if let Some(ref id) = self.base_scan_config_id {
            validate_uuid("baseScanConfigId", id)?;
        }

        Ok(CreateScanConfigInput {
            name,
            comment: self.comment,
            base_scan_config_id: self.base_scan_config_id,
        })
    }
}

/// Modify-scan-config request payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(rename = "ModifyScanConfig")]
pub struct ModifyScanConfigRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl ModifyScanConfigRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyScanConfigInput, GatewayError> {
        Ok(ModifyScanConfigInput {
            name: self.name,
            comment: self.comment,
        })
    }
}

/// List scan configs handler.
pub async fn list_scan_configs(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ScanConfigListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_scan_configs(
            &session,
            ScanConfigQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(scan_configs) => (
            StatusCode::OK,
            Json(ScanConfigListResponse::from(scan_configs)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Create scan config handler.
pub async fn create_scan_config(
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
    let request = match serde_json::from_slice::<CreateScanConfigRequest>(&body) {
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

    match service.create_scan_config(&session, input).await {
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

/// Get scan config handler.
pub async fn get_scan_config(
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

    match service.get_scan_config(&session, &id).await {
        Ok(scan_config) => {
            (StatusCode::OK, Json(ScanConfigResponse::from(scan_config))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Update scan config handler.
pub async fn update_scan_config(
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
    let request = match serde_json::from_slice::<ModifyScanConfigRequest>(&body) {
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

    match service.modify_scan_config(&session, &id, input).await {
        Ok(scan_config) => {
            (StatusCode::OK, Json(ScanConfigResponse::from(scan_config))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Delete scan config handler.
pub async fn delete_scan_config(
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

    match service.delete_scan_config(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/scan-configs`.
pub(crate) fn list_scan_configs_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigs")
        .tag("Scan Configs")
        .summary("List scan configurations")
        .description("Returns a paginated list of scan configurations.")
        .security_requirement("bearerAuth")
        .input::<Query<ScanConfigListQueryDoc>>()
        .response_with::<200, Json<ScanConfigListResponse>, _>(ok_json(
            "Paginated list of scan configs",
        ));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/scan-configs`.
pub(crate) fn create_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createScanConfig")
        .tag("Scan Configs")
        .summary("Create a scan configuration")
        .description("Creates a new scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateScanConfigRequest>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Scan config created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/scan-configs/{id}`.
pub(crate) fn get_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfig")
        .tag("Scan Configs")
        .summary("Get a scan configuration")
        .description("Returns the details for a single scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/scan-configs/{id}`.
pub(crate) fn update_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyScanConfig")
        .tag("Scan Configs")
        .summary("Modify a scan configuration")
        .description("Updates an existing scan configuration.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyScanConfigRequest>)>()
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/scan-configs/{id}`.
pub(crate) fn delete_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteScanConfig")
        .tag("Scan Configs")
        .summary("Delete a scan configuration")
        .description("Deletes an existing scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Scan config deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
