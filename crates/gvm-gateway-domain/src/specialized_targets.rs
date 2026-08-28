// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OCI image and web application target domain contracts.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Collection query shared by specialized target families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpecializedTargetQuery {
    /// Optional inline GMP filter.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Whether to list trashcan resources.
    pub trash: bool,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// OCI image target representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OciImageTarget {
    /// Target identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// OCI image references to scan.
    #[serde(rename = "imageReferences")]
    pub image_references: Vec<String>,
    /// Optional registry credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<ResourceRef>,
    /// Tasks using the target.
    pub tasks: Vec<ResourceRef>,
    /// Whether the target is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the target is writable.
    pub writable: bool,
}

/// Paginated OCI image target list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OciImageTargetPage {
    /// Page items.
    pub data: Vec<OciImageTarget>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// OCI image target creation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOciImageTargetInput {
    /// Display name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// OCI image references to scan.
    pub image_references: Vec<String>,
    /// Optional registry credential identifier.
    pub credential_id: Option<String>,
}

/// OCI image target modification input.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyOciImageTargetInput {
    /// Optional display name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional replacement image references.
    pub image_references: Option<Vec<String>>,
    /// Optional registry credential identifier.
    pub credential_id: Option<String>,
}

/// Web application target representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebApplicationTarget {
    /// Target identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// URLs to scan.
    pub urls: Vec<String>,
    /// URLs excluded from the scan.
    #[serde(rename = "excludeUrls")]
    pub exclude_urls: Vec<String>,
    /// Optional HTTP credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<ResourceRef>,
    /// Tasks using the target.
    pub tasks: Vec<ResourceRef>,
    /// Whether the target is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the target is writable.
    pub writable: bool,
}

/// Paginated web application target list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebApplicationTargetPage {
    /// Page items.
    pub data: Vec<WebApplicationTarget>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Web application target creation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateWebApplicationTargetInput {
    /// Display name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// URLs to scan.
    pub urls: Vec<String>,
    /// URLs excluded from the scan.
    pub exclude_urls: Vec<String>,
    /// Optional HTTP credential identifier.
    pub credential_id: Option<String>,
}

/// Web application target modification input.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyWebApplicationTargetInput {
    /// Optional display name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional replacement URLs.
    pub urls: Option<Vec<String>>,
    /// Optional replacement excluded URLs.
    pub exclude_urls: Option<Vec<String>>,
    /// Optional HTTP credential identifier.
    pub credential_id: Option<String>,
}
