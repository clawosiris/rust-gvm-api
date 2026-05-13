// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scanner domain types and query options.

use serde::{Deserialize, Serialize};

use crate::Pagination;

/// Domain scanner representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Scanner {
    /// Scanner identifier.
    pub id: String,
    /// Scanner name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Scanner host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Scanner port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    /// Scanner type (e.g. "OpenVAS", "CVE", "OSP").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub scanner_type: Option<String>,
}

/// Paginated scanner list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScannerPage {
    /// Page items.
    pub data: Vec<Scanner>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Scanner list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScannerQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}
