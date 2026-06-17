// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report export job DTOs, handlers, and OpenAPI transforms.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, State},
    http::{
        header::{self, HeaderValue},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateReportExportRequest, GatewayError, GvmdReportFormatExportRequest, JobCancelOutcome,
    JsonReportExportRequest, ReportExportFormat, ReportExportJob,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::ResourceRefResponse,
    error::RestError,
    openapi::{ok_json, problem_response, ResourceIdPathDoc},
    router::bearer_token,
    targets::validate_uuid,
};

/// JSON request body for `POST /reports/{id}/exports`.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum CreateReportExportRequestBody {
    /// gvmd report-format export request.
    GvmdReportFormat(GvmdReportFormatExportRequestBody),
    /// Gateway JSON export request.
    Json(JsonReportExportRequestBody),
}

/// gvmd report-format export request body.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct GvmdReportFormatExportRequestBody {
    #[serde(rename = "reportFormatId")]
    report_format_id: String,
    #[serde(rename = "reportConfigId")]
    report_config_id: Option<String>,
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<String>,
}

/// Gateway JSON export request body.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonReportExportRequestBody {
    format: JsonExportFormatBody,
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<String>,
}

/// Supported explicit export format selector.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum JsonExportFormatBody {
    Json,
}

impl CreateReportExportRequestBody {
    fn into_domain(self) -> Result<CreateReportExportRequest, GatewayError> {
        match self {
            Self::GvmdReportFormat(body) => {
                validate_uuid("reportFormatId", &body.report_format_id)?;
                if let Some(report_config_id) = &body.report_config_id {
                    validate_uuid("reportConfigId", report_config_id)?;
                }
                if let Some(filter_id) = &body.filter_id {
                    validate_uuid("filterId", filter_id)?;
                }
                Ok(CreateReportExportRequest::GvmdReportFormat(
                    GvmdReportFormatExportRequest {
                        report_format_id: body.report_format_id,
                        report_config_id: body.report_config_id,
                        filter: body.filter,
                        filter_id: body.filter_id,
                    },
                ))
            }
            Self::Json(body) => {
                match body.format {
                    JsonExportFormatBody::Json => {}
                }
                if let Some(filter_id) = &body.filter_id {
                    validate_uuid("filterId", filter_id)?;
                }
                Ok(CreateReportExportRequest::Json(JsonReportExportRequest {
                    filter: body.filter,
                    filter_id: body.filter_id,
                }))
            }
        }
    }
}

/// Public job status response value.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum JobStatusResponse {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelling,
    Cancelled,
    Expired,
}

/// Public report export format response value.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ReportExportFormatResponse {
    GvmdReportFormat,
    Json,
}

/// JSON job progress response.
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct JobProgressResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// JSON job result metadata response.
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct JobResultResponse {
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
}

/// JSON job problem response.
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct JobProblemResponse {
    r#type: String,
    code: String,
    title: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// JSON body returned for report export jobs.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReportExportJob")]
pub(crate) struct ReportExportJobResponse {
    id: Uuid,
    kind: String,
    status: JobStatusResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<JobProgressResponse>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    #[serde(rename = "completedAt", skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(rename = "resultLocation", skip_serializing_if = "Option::is_none")]
    result_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JobProblemResponse>,
    report: ResourceRefResponse,
    format: ReportExportFormatResponse,
    #[serde(rename = "reportFormatId", skip_serializing_if = "Option::is_none")]
    report_format_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<JobResultResponse>,
}

impl From<ReportExportJob> for ReportExportJobResponse {
    fn from(job: ReportExportJob) -> Self {
        Self {
            id: job.id.parse().unwrap_or_else(|_| Uuid::nil()),
            kind: job.kind,
            status: match job.status {
                gvm_gateway_domain::JobStatus::Queued => JobStatusResponse::Queued,
                gvm_gateway_domain::JobStatus::Running => JobStatusResponse::Running,
                gvm_gateway_domain::JobStatus::Succeeded => JobStatusResponse::Succeeded,
                gvm_gateway_domain::JobStatus::Failed => JobStatusResponse::Failed,
                gvm_gateway_domain::JobStatus::Cancelling => JobStatusResponse::Cancelling,
                gvm_gateway_domain::JobStatus::Cancelled => JobStatusResponse::Cancelled,
                gvm_gateway_domain::JobStatus::Expired => JobStatusResponse::Expired,
            },
            progress: job.progress.map(|progress| JobProgressResponse {
                percent: progress.percent,
                message: progress.message,
            }),
            created_at: job.created_at,
            started_at: job.started_at,
            completed_at: job.completed_at,
            expires_at: job.expires_at,
            result_location: job.result_location,
            error: job.error.map(|error| JobProblemResponse {
                r#type: error.r#type,
                code: error.code,
                title: error.title,
                status: error.status,
                detail: error.detail,
            }),
            report: ResourceRefResponse::from(job.report),
            format: match job.format {
                ReportExportFormat::GvmdReportFormat => {
                    ReportExportFormatResponse::GvmdReportFormat
                }
                ReportExportFormat::Json => ReportExportFormatResponse::Json,
            },
            report_format_id: job.report_format_id.and_then(|id| id.parse::<Uuid>().ok()),
            result: job.result.map(|result| JobResultResponse {
                content_type: result.content_type,
                filename: result.filename,
                size: result.size,
                location: result.location,
            }),
        }
    }
}

/// Starts an asynchronous report export.
pub(crate) async fn create_report_export_job(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    Json(body): Json<CreateReportExportRequestBody>,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let request = match body.into_domain() {
        Ok(request) => request,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .create_report_export_job(&session, &id, request)
        .await
    {
        Ok(job) => {
            let location = format!("/api/v1/jobs/{}", job.id);
            (
                StatusCode::ACCEPTED,
                [
                    (header::LOCATION, location),
                    (header::RETRY_AFTER, "1".to_string()),
                ],
                Json(ReportExportJobResponse::from(job)),
            )
                .into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Gets asynchronous job status.
pub(crate) async fn get_job(
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

    match service.get_job(&session, &id).await {
        Ok(job) => (StatusCode::OK, Json(ReportExportJobResponse::from(job))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Cancels an asynchronous job.
pub(crate) async fn cancel_job(
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

    match service.cancel_job(&session, &id).await {
        Ok(JobCancelOutcome::CancellationRequested) => StatusCode::ACCEPTED.into_response(),
        Ok(JobCancelOutcome::AlreadyTerminal) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Downloads a completed job result.
pub(crate) async fn download_job_result(
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

    match service.download_job_result(&session, &id).await {
        Ok(artifact) => {
            let mut response = artifact.bytes.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&artifact.content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{}\"", artifact.filename))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            response
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// OpenAPI transform for `POST /api/v1/reports/{id}/exports`.
pub(crate) fn create_report_export_job_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createReportExportJob")
        .tag("Report Exports")
        .summary("Start an asynchronous report export")
        .description(
            "Starts rendering a report artifact in the selected report format. Jobs are scoped to the authenticated user that created them.",
        )
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<CreateReportExportRequestBody>)>()
        .response_with::<202, Json<ReportExportJobResponse>, _>(ok_json(
            "Report export job accepted",
        ));

    let op = problem_response::<400>(op, "Invalid report export request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<429>(op, "Job capacity exceeded");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/jobs/{id}`.
pub(crate) fn get_job_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getJob")
        .tag("Jobs")
        .summary("Get asynchronous job status")
        .description("Returns status only for jobs created by the authenticated user.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ReportExportJobResponse>, _>(ok_json("Job status"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/jobs/{id}`.
pub(crate) fn cancel_job_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("cancelJob")
        .tag("Jobs")
        .summary("Cancel an asynchronous job")
        .description("Cancels a job created by the authenticated user.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<202, (), _>(|response| response.description("Cancellation requested"))
        .response_with::<204, (), _>(|response| {
            response.description("Job already reached a terminal state")
        });

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

/// OpenAPI transform for `GET /api/v1/jobs/{id}/result`.
pub(crate) fn download_job_result_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("downloadJobResult")
        .tag("Jobs")
        .summary("Download a completed job result")
        .description(
            "Downloads the artifact produced by a completed report export job for the authenticated user that created it.",
        )
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, (), _>(|response| response.description("Rendered report artifact"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Job result is not available")
}

#[cfg(test)]
#[path = "jobs_test.rs"]
mod jobs_test;
