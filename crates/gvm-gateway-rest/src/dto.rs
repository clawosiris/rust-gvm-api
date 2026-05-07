// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared REST response DTOs used across multiple handler modules.

use gvm_gateway_domain::{Pagination, ResourceRef};
use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

/// Parse a string as a UUID, falling back to the nil UUID on failure.
pub(crate) fn parse_uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap_or_default()
}

/// Custom JSON Schema for date-time formatted strings.
pub(crate) fn datetime_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "format": "date-time"
    })
}

/// Pagination metadata for list responses.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Pagination")]
pub(crate) struct PaginationResponse {
    page: u32,
    #[serde(rename = "perPage")]
    per_page: u32,
    total: u32,
    #[serde(rename = "totalPages")]
    total_pages: u32,
}

impl From<Pagination> for PaginationResponse {
    fn from(p: Pagination) -> Self {
        Self {
            page: p.page,
            per_page: p.per_page,
            total: p.total,
            total_pages: p.total_pages,
        }
    }
}

/// Minimal reference to a related resource.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ResourceRef")]
pub(crate) struct ResourceRefResponse {
    id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

impl From<ResourceRef> for ResourceRefResponse {
    fn from(r: ResourceRef) -> Self {
        Self {
            id: parse_uuid(&r.id),
            name: r.name,
        }
    }
}

/// Response body for resource creation endpoints.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ResourceCreated")]
pub(crate) struct ResourceCreatedResponse {
    pub(crate) id: Uuid,
}
