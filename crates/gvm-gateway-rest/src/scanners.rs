// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scanner DTOs, request parsing, handlers, and response mapping for the REST adapter.

use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{GatewayError, ScannerQuery};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{parse_uuid, PaginationResponse},
    error::RestError,
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// Scanner type.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) enum ScannerType {
    #[serde(rename = "OpenVAS")]
    OpenVas,
    #[serde(rename = "CVE")]
    Cve,
    #[serde(rename = "OSP")]
    Osp,
}

fn parse_scanner_type(s: &str) -> Option<ScannerType> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// JSON body returned for a single scanner.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Scanner")]
pub(crate) struct ScannerResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u32>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    scanner_type: Option<ScannerType>,
}

impl From<gvm_gateway_domain::Scanner> for ScannerResponse {
    fn from(s: gvm_gateway_domain::Scanner) -> Self {
        Self {
            id: parse_uuid(&s.id),
            name: s.name,
            comment: s.comment,
            host: s.host,
            port: s.port,
            scanner_type: s.scanner_type.as_deref().and_then(parse_scanner_type),
        }
    }
}

/// JSON body returned for a paginated list of scanners.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ScannerList")]
pub(crate) struct ScannerListResponse {
    data: Vec<ScannerResponse>,
    pagination: PaginationResponse,
}

impl From<gvm_gateway_domain::ScannerPage> for ScannerListResponse {
    fn from(page: gvm_gateway_domain::ScannerPage) -> Self {
        Self {
            data: page.data.into_iter().map(ScannerResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-scanners query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannerListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ScannerListQuery {
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

/// List scanners handler.
pub async fn list_scanners(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ScannerListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_scanners(
            &session,
            ScannerQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(scanners) => (StatusCode::OK, Json(ScannerListResponse::from(scanners))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get scanner handler.
pub async fn get_scanner(
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

    match service.get_scanner(&session, &id).await {
        Ok(scanner) => (StatusCode::OK, Json(ScannerResponse::from(scanner))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}
