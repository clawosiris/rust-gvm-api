// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared value objects used across gateway resources.

use serde::{Deserialize, Serialize};

/// Minimal reference to a related resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    /// Resource identifier.
    pub id: String,
    /// Optional resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Pagination metadata for list responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pagination {
    /// Current page.
    pub page: u32,
    /// Page size.
    #[serde(rename = "perPage")]
    pub per_page: u32,
    /// Total matching resources.
    pub total: u32,
    /// Total number of pages.
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}
