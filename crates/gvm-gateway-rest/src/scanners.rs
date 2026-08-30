// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scanner DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
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
    dto::{parse_uuid, PaginationResponse, ResourceRefResponse},
    error::RestError,
    open_enum::open_string_enum,
    openapi::{ok_json, problem_response, ResourceIdPathDoc},
    query::parse_collection_query,
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

open_string_enum! {
    /// Scanner type.
    pub(crate) enum ScannerType {
        OpenVas => "OpenVAS",
        Cve => "CVE",
        Osp => "OSP",
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<ResourceRefResponse>,
    #[serde(rename = "caPub", skip_serializing_if = "Option::is_none")]
    ca_pub: Option<String>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

impl From<gvm_gateway_domain::Scanner> for ScannerResponse {
    fn from(s: gvm_gateway_domain::Scanner) -> Self {
        Self {
            id: parse_uuid(&s.id),
            name: s.name,
            comment: s.comment,
            host: s.host,
            port: s.port,
            scanner_type: s.scanner_type.as_deref().map(ScannerType::parse),
            credential: s.credential.map(ResourceRefResponse::from),
            ca_pub: s.ca_pub,
            in_use: s.in_use,
            writable: s.writable,
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

/// OpenAPI query parameter schema for the list-scanners endpoint.
///
/// This struct drives the generated OpenAPI schema. The runtime handler uses
/// [`ScannerListQuery`] with manual parsing from [`OriginalUri`] instead.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ScannerListQueryParams {
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

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
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
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
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

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/scanners`.
pub(crate) fn list_scanners_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanners")
        .tag("Scanners")
        .summary("List scanners")
        .description("Returns a paginated list of scanners.")
        .security_requirement("bearerAuth")
        .input::<Query<ScannerListQueryParams>>()
        .response_with::<200, Json<ScannerListResponse>, _>(ok_json("Paginated list of scanners"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/scanners/{id}`.
pub(crate) fn get_scanner_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanner")
        .tag("Scanners")
        .summary("Get a scanner")
        .description("Returns the details for a single scanner.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScannerResponse>, _>(ok_json("Scanner details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "scanners_test.rs"]
mod scanners_test;
