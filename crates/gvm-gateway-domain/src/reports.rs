// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report domain types and query options.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef, ScanResult};

/// Domain report representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Report {
    /// Report identifier.
    pub id: String,
    /// Associated task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Scan start timestamp.
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    pub scan_start: Option<String>,
    /// Scan end timestamp.
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    pub scan_end: Option<String>,
    /// Highest severity found in the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Result counts by severity category.
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    pub result_count: Option<ResultCount>,
    /// Embedded results (when fetching a single report).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ScanResult>,
}

/// Result counts by severity category for a report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResultCount {
    /// Total number of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    /// Number of high-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u32>,
    /// Number of medium-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,
    /// Number of low-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low: Option<u32>,
    /// Number of log-level results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<u32>,
    /// Number of debug-level results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<u32>,
    /// Number of false-positive results.
    #[serde(rename = "falsePositive", skip_serializing_if = "Option::is_none")]
    pub false_positive: Option<u32>,
}

/// Paginated report list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportPage {
    /// Page items.
    pub data: Vec<Report>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Exported report artifact for download-style responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportExport {
    /// Rendered report bytes in the selected report format.
    pub bytes: Vec<u8>,
    /// Content type reported by the backend when available.
    pub content_type: Option<String>,
    /// File extension reported by the backend when available.
    pub extension: Option<String>,
}

/// TLS certificate observation associated with a report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificate {
    /// Backend certificate or observation identifier when available.
    pub id: Option<String>,
    /// Host associated with the certificate.
    pub host: Option<String>,
    /// Port associated with the certificate.
    pub port: Option<String>,
    /// Subject distinguished name or other primary label.
    pub subject: String,
    /// Optional issuer distinguished name.
    pub issuer: Option<String>,
    /// Optional certificate activation timestamp.
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional certificate expiration timestamp.
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Optional SHA-256 fingerprint.
    #[serde(rename = "fingerprintSha256", skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
}

/// Paginated TLS certificate list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlsCertificatePage {
    /// Page items.
    pub data: Vec<TlsCertificate>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Report list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Options for fetching a single report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportOpts {
    /// Whether to ignore embedded-result pagination and return all results.
    pub ignore_pagination: bool,
    /// Requested embedded-result page number.
    pub page: u32,
    /// Requested embedded-result page size.
    pub per_page: u32,
}

impl Default for GetReportOpts {
    fn default() -> Self {
        Self {
            ignore_pagination: false,
            page: 1,
            per_page: 25,
        }
    }
}
