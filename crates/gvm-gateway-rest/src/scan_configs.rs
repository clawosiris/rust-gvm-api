// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scan config DTOs, request parsing, handlers, and response mapping for the REST adapter.

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateScanConfigInput, GatewayError, ModifyScanConfigInput, ScanConfigQuery,
};
use serde::Deserialize;

use crate::{error::RestError, router::bearer_token, targets::validate_uuid};

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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CreateScanConfigRequest {
    /// Optional name so validation can return RFC 9457 instead of extractor failures.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional base scan config identifier to copy from.
    #[serde(rename = "baseScanConfigId")]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
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
        Ok(scan_configs) => (StatusCode::OK, Json(scan_configs)).into_response(),
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
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
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
        Ok(scan_config) => (StatusCode::OK, Json(scan_config)).into_response(),
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
        Ok(scan_config) => (StatusCode::OK, Json(scan_config)).into_response(),
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
