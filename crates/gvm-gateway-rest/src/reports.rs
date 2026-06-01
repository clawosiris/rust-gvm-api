// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{
        header::{self, HeaderValue},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    GatewayError, GetReportOpts, ReportQuery, ResultQuery, TlsCertificate, TlsCertificatePage,
};
use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    dto::{datetime_schema, parse_uuid, PaginationResponse, ResourceRefResponse},
    error::RestError,
    openapi::{
        ok_json, problem_response, GetReportQueryDoc, ReportExportQueryDoc, ReportListQueryDoc,
        ReportResultsQueryDoc, ResourceIdPathDoc,
    },
    results::{ResultListResponse, ResultResponse},
    router::bearer_token,
    targets::validate_uuid,
};

// ============================================================================
// Response DTOs
// ============================================================================

/// Result counts by severity category.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ResultCount")]
pub(crate) struct ResultCountResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    high: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    medium: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    low: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<u32>,
    #[serde(rename = "falsePositive", skip_serializing_if = "Option::is_none")]
    false_positive: Option<u32>,
}

impl From<gvm_gateway_domain::ResultCount> for ResultCountResponse {
    fn from(rc: gvm_gateway_domain::ResultCount) -> Self {
        Self {
            total: rc.total,
            high: rc.high,
            medium: rc.medium,
            low: rc.low,
            log: rc.log,
            false_positive: rc.false_positive,
        }
    }
}

/// JSON body returned for a single report.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Report")]
pub(crate) struct ReportResponse {
    id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ResourceRefResponse>,
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    scan_start: Option<String>,
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    scan_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<f64>,
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    result_count: Option<ResultCountResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    results: Vec<ResultResponse>,
}

impl From<gvm_gateway_domain::Report> for ReportResponse {
    fn from(r: gvm_gateway_domain::Report) -> Self {
        Self {
            id: parse_uuid(&r.id),
            task: r.task.map(ResourceRefResponse::from),
            scan_start: r.scan_start,
            scan_end: r.scan_end,
            severity: r.severity,
            result_count: r.result_count.map(ResultCountResponse::from),
            results: r.results.into_iter().map(ResultResponse::from).collect(),
        }
    }
}

/// JSON body returned for a paginated list of reports.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportList")]
pub(crate) struct ReportListResponse {
    data: Vec<ReportResponse>,
    pagination: PaginationResponse,
}

/// JSON body returned for a TLS certificate observation.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificate")]
pub(crate) struct TlsCertificateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    not_before: Option<String>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    not_after: Option<String>,
    #[serde(rename = "fingerprintSha256", skip_serializing_if = "Option::is_none")]
    fingerprint_sha256: Option<String>,
}

impl From<TlsCertificate> for TlsCertificateResponse {
    fn from(certificate: TlsCertificate) -> Self {
        Self {
            id: certificate.id,
            host: certificate.host,
            port: certificate.port,
            subject: certificate.subject,
            issuer: certificate.issuer,
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            fingerprint_sha256: certificate.fingerprint_sha256,
        }
    }
}

/// JSON body returned for a paginated TLS certificate list.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "TlsCertificateList")]
pub(crate) struct TlsCertificateListResponse {
    data: Vec<TlsCertificateResponse>,
    pagination: PaginationResponse,
}

impl From<TlsCertificatePage> for TlsCertificateListResponse {
    fn from(page: TlsCertificatePage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(TlsCertificateResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

impl From<gvm_gateway_domain::ReportPage> for ReportListResponse {
    fn from(page: gvm_gateway_domain::ReportPage) -> Self {
        Self {
            data: page.data.into_iter().map(ReportResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

/// Parsed list-reports query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportListQuery {
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

/// Parsed query parameters for GET /reports/{id} endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportQuery {
    /// Whether to ignore pagination and return all results.
    pub ignore_pagination: bool,
}

impl GetReportQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Self {
        let mut ignore_pagination = false;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if key == "ignorePagination" {
                ignore_pagination = value == "true";
            }
        }

        Self { ignore_pagination }
    }
}

/// Parsed query for report results sub-resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportResultsQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportResultsQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut filter_string = None;
        let mut page = None;
        let mut per_page = None;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                "filter" => filter_string = Some(value.to_string()),
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
            page,
            per_page,
        })
    }
}

/// Parsed query for report export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportExportQuery {
    /// Backend report format identifier used to render the export.
    pub report_format_id: String,
}

impl ReportExportQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if key == "reportFormatId" {
                validate_uuid("reportFormatId", value)?;
                return Ok(Self {
                    report_format_id: value.to_string(),
                });
            }
        }

        Err(GatewayError::InvalidInput(
            "reportFormatId is required".to_string(),
        ))
    }
}

/// List reports handler.
pub async fn list_reports(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ReportListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_reports(
            &session,
            ReportQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(reports) => (StatusCode::OK, Json(ReportListResponse::from(reports))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report handler.
pub async fn get_report(
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
    let query = GetReportQuery::try_from_query_string(uri.query().unwrap_or(""));

    match service
        .get_report(
            &session,
            &id,
            GetReportOpts {
                ignore_pagination: query.ignore_pagination,
            },
        )
        .await
    {
        Ok(report) => (StatusCode::OK, Json(ReportResponse::from(report))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Export report handler.
pub async fn export_report(
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
    let query = match ReportExportQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .export_report(&session, &id, &query.report_format_id)
        .await
    {
        Ok(export) => {
            let content_type = export
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let extension = export.extension.unwrap_or_else(|| "bin".to_string());
            let filename = format!("report-{id}.{extension}");
            let mut response = export.bytes.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            response
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Delete report handler.
pub async fn delete_report(
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

    match service.delete_report(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report results handler.
pub async fn get_report_results(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_results(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (
            StatusCode::OK,
            Json(crate::results::ResultListResponse::from(results)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report vulnerabilities handler.
pub async fn get_report_vulnerabilities(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_vulnerabilities(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (StatusCode::OK, Json(ResultListResponse::from(results))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report TLS certificates handler.
pub async fn get_report_tls_certificates(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_tls_certificates(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(certificates) => (
            StatusCode::OK,
            Json(TlsCertificateListResponse::from(certificates)),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report errors handler.
pub async fn get_report_errors(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_errors(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (StatusCode::OK, Json(ResultListResponse::from(results))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report closed CVEs handler.
pub async fn get_report_closed_cves(
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
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_closed_cves(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (StatusCode::OK, Json(ResultListResponse::from(results))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /api/v1/reports`.
pub(crate) fn list_reports_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReports")
        .tag("Reports")
        .summary("List reports")
        .description("Returns a paginated list of reports.")
        .security_requirement("bearerAuth")
        .input::<Query<ReportListQueryDoc>>()
        .response_with::<200, Json<ReportListResponse>, _>(ok_json("Paginated list of reports"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}`.
pub(crate) fn get_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReport")
        .tag("Reports")
        .summary("Get a report")
        .description("Returns the details for a single report with embedded results.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<GetReportQueryDoc>)>()
        .response_with::<200, Json<ReportResponse>, _>(ok_json(
            "Report details with embedded results",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/export`.
pub(crate) fn export_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("exportReport")
        .tag("Reports")
        .summary("Export a report in a selected report format")
        .description("Returns rendered report bytes for a selected report format.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportExportQueryDoc>)>()
        .response_with::<200, (), _>(|response| response.description("Rendered report bytes"));

    let op = problem_response::<400>(op, "Missing or invalid reportFormatId");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/reports/{id}`.
pub(crate) fn delete_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteReport")
        .tag("Reports")
        .summary("Delete a report")
        .description("Deletes an existing report.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Report deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/results`.
pub(crate) fn get_report_results_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportResults")
        .tag("Reports")
        .summary("Get paginated results for a report")
        .description("Returns a paginated list of results for a specific report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json("Paginated list of results"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/vulnerabilities`.
pub(crate) fn get_report_vulnerabilities_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getReportVulnerabilities")
        .tag("Reports")
        .summary("Get vulnerability findings for a report")
        .description("Returns a paginated list of vulnerability findings for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json(
            "Paginated list of vulnerability findings",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/tls-certificates`.
pub(crate) fn get_report_tls_certificates_docs(
    op: TransformOperation<'_>,
) -> TransformOperation<'_> {
    let op = op
        .id("getReportTlsCertificates")
        .tag("Reports")
        .summary("Get TLS certificates observed in a report")
        .description("Returns a paginated list of TLS certificate observations for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<TlsCertificateListResponse>, _>(ok_json(
            "Paginated list of TLS certificates",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/errors`.
pub(crate) fn get_report_errors_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportErrors")
        .tag("Reports")
        .summary("Get report error findings")
        .description("Returns a paginated list of report error findings.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json(
            "Paginated list of report errors",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/closed-cves`.
pub(crate) fn get_report_closed_cves_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportClosedCves")
        .tag("Reports")
        .summary("Get closed CVE findings for a report")
        .description("Returns a paginated list of closed-CVE findings for a report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json(
            "Paginated list of closed CVE findings",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}
