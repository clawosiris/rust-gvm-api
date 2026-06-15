// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Domain types for asynchronous gateway jobs.

use serde::{Deserialize, Serialize};

use crate::{GatewayErrorCode, Report, ResourceRef, ScanResult};

/// Request to create a report export job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateReportExportRequest {
    /// Export through a gvmd report format plugin.
    GvmdReportFormat(GvmdReportFormatExportRequest),
    /// Export the gateway JSON representation.
    Json(JsonReportExportRequest),
}

/// Report export request backed by a gvmd report format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GvmdReportFormatExportRequest {
    /// UUID of the report format used by gvmd.
    pub report_format_id: String,
    /// Optional report configuration identifier.
    pub report_config_id: Option<String>,
    /// Optional GMP filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
}

/// Report export request for the gateway JSON format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonReportExportRequest {
    /// Optional GMP filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
}

/// Asynchronous job status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Job is accepted but has not started.
    Queued,
    /// Job is currently running.
    Running,
    /// Job completed successfully.
    Succeeded,
    /// Job failed.
    Failed,
    /// Cancellation has been requested.
    Cancelling,
    /// Job was cancelled.
    Cancelled,
    /// Job metadata or artifact expired.
    Expired,
}

impl JobStatus {
    /// Whether this status is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

/// Job progress information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobProgress {
    /// Completion percentage when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Human-readable progress message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Job result metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobResult {
    /// Artifact content type.
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Suggested download filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Artifact size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Result download location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Public problem shape stored on failed jobs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobProblem {
    /// Problem type URI.
    pub r#type: String,
    /// Stable machine-readable problem identity.
    pub code: String,
    /// Human-readable summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Occurrence-specific detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl JobProblem {
    /// Build a public job problem from a gateway error.
    pub fn from_gateway_error(error: &crate::GatewayError) -> Self {
        let code = error.code();
        Self {
            r#type: format!(
                "https://gvm-gateway.greenbone.net/errors/{}",
                code.problem_slug()
            ),
            code: code.as_str().to_string(),
            title: title_for_code(code).to_string(),
            status: status_for_code(code),
            detail: Some(error.detail().to_string()),
        }
    }
}

/// Report export format kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportExportFormat {
    /// gvmd report format plugin export.
    GvmdReportFormat,
    /// Gateway JSON export.
    Json,
}

/// Public report export job representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportExportJob {
    /// Job identifier.
    pub id: String,
    /// Job kind.
    pub kind: String,
    /// Job status.
    pub status: JobStatus,
    /// Job progress when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<JobProgress>,
    /// Job creation time.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Job start time.
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Job completion time.
    #[serde(rename = "completedAt", skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Job expiry time.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Result download location.
    #[serde(rename = "resultLocation", skip_serializing_if = "Option::is_none")]
    pub result_location: Option<String>,
    /// Failure problem details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JobProblem>,
    /// Exported report reference.
    pub report: ResourceRef,
    /// Export format kind.
    pub format: ReportExportFormat,
    /// gvmd report format identifier.
    #[serde(rename = "reportFormatId", skip_serializing_if = "Option::is_none")]
    pub report_format_id: Option<String>,
    /// Result metadata when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
}

/// Completed job artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobArtifact {
    /// Artifact bytes.
    pub bytes: Vec<u8>,
    /// Artifact content type.
    pub content_type: String,
    /// Suggested download filename.
    pub filename: String,
}

/// Outcome of a cancellation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobCancelOutcome {
    /// Cancellation was requested for a non-terminal job.
    CancellationRequested,
    /// The job was already in a terminal state.
    AlreadyTerminal,
}

/// Gateway JSON report export artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportJsonExport {
    /// Report metadata.
    pub report: Report,
    /// Exported report results.
    pub results: Vec<ScanResult>,
    /// Export generation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
}

fn status_for_code(code: GatewayErrorCode) -> u16 {
    match code {
        GatewayErrorCode::BackendUnavailable => 502,
        GatewayErrorCode::NotImplemented => 501,
        GatewayErrorCode::NotFound => 404,
        GatewayErrorCode::BadRequest => 400,
        GatewayErrorCode::Unauthorized
        | GatewayErrorCode::SessionExpired
        | GatewayErrorCode::SessionInvalidated => 401,
        GatewayErrorCode::Forbidden => 403,
        GatewayErrorCode::Conflict => 409,
        GatewayErrorCode::TooManyRequests => 429,
        GatewayErrorCode::InternalServerError => 500,
        GatewayErrorCode::GatewayTimeout => 504,
    }
}

fn title_for_code(code: GatewayErrorCode) -> &'static str {
    match code {
        GatewayErrorCode::BackendUnavailable => "Bad Gateway",
        GatewayErrorCode::NotImplemented => "Not Implemented",
        GatewayErrorCode::NotFound => "Not Found",
        GatewayErrorCode::BadRequest => "Bad Request",
        GatewayErrorCode::Unauthorized => "Unauthorized",
        GatewayErrorCode::SessionExpired => "Session Expired",
        GatewayErrorCode::SessionInvalidated => "Session Invalidated",
        GatewayErrorCode::Forbidden => "Forbidden",
        GatewayErrorCode::Conflict => "Conflict",
        GatewayErrorCode::TooManyRequests => "Too Many Requests",
        GatewayErrorCode::InternalServerError => "Internal Server Error",
        GatewayErrorCode::GatewayTimeout => "Gateway Timeout",
    }
}
