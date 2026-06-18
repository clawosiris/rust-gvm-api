// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report DTOs, request parsing, handlers, and response mapping for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
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
        ok_json, problem_response, GetReportQueryDoc, ReportListQueryDoc, ReportResultsQueryDoc,
        ResourceIdPathDoc,
    },
    query::{parse_collection_query, parse_delete_resource_query, DeleteResourceQueryParams},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<u32>,
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
            debug: rc.debug,
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
    #[schemars(length(max = 1000))]
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
    #[schemars(length(max = 1000))]
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
    #[schemars(length(max = 1000))]
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
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// Parsed query parameters for GET /reports/{id} endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportQuery {
    /// Embedded-result page number.
    pub page: u32,
    /// Embedded-result page size.
    pub per_page: u32,
}

impl GetReportQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }
}

/// Parsed query for report results sub-resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportResultsQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportResultsQuery {
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
    let query = match GetReportQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report(
            &session,
            &id,
            GetReportOpts {
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(report) => (StatusCode::OK, Json(ReportResponse::from(report))).into_response(),
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

    let ultimate = match parse_delete_resource_query(uri.query().unwrap_or("")) {
        Ok(ultimate) => ultimate,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    match service.delete_report(&session, &id, ultimate).await {
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
                filter_id: query.filter_id,
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
                filter_id: query.filter_id,
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
                filter_id: query.filter_id,
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
                filter_id: query.filter_id,
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
                filter_id: query.filter_id,
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
        .description(
            "Returns the details for a single report with embedded results from the requested `page` and `perPage` window.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<GetReportQueryDoc>)>()
        .response_with::<200, Json<ReportResponse>, _>(ok_json(
            "Report details with embedded results from the requested embedded-result window",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/reports/{id}`.
pub(crate) fn delete_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteReport")
        .tag("Reports")
        .summary("Delete a report")
        .description("Deletes a report. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
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
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
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
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
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
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
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
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<501>(
        op,
        "The connected gvmd backend does not implement this report-detail operation",
    )
}

#[cfg(test)]
#[path = "reports_test.rs"]
mod reports_test;
