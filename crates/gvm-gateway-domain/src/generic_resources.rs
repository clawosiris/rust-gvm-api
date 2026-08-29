// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Generic asset and config domain types used by the reserved combined
//! resource endpoints.

use serde::{Deserialize, Serialize};

use crate::{Pagination, SupportingResourceMeta};

/// Generic asset list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssetQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
    /// Optional asset type discriminator.
    pub asset_type: Option<String>,
}

/// Generic config list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GenericConfigQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
    /// Optional config usage-type discriminator.
    pub usage_type: Option<String>,
}

/// Generic asset update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyAssetInput {
    /// Optional comment.
    pub comment: Option<String>,
}

/// Generic asset identifier emitted by gvmd for non-host asset families.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetIdentifier {
    /// Optional identifier name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional identifier value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional identifier source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Host summary embedded in operating-system asset responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetHost {
    /// Host identifier.
    pub id: String,
    /// Host name.
    pub name: String,
    /// Optional host severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Combined generic asset representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenericAsset {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: SupportingResourceMeta,
    /// Open backend asset-type discriminator.
    #[serde(rename = "type")]
    pub asset_type: String,
    /// Optional asset value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional asset identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<AssetIdentifier>,
    /// Optional asset severity summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Optional host IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Optional host name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Optional detected operating system for host assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Optional operating-system host count.
    #[serde(rename = "hostsCount", skip_serializing_if = "Option::is_none")]
    pub hosts_count: Option<u32>,
    /// Optional operating-system title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional operating-system install count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installs: Option<u32>,
    /// Optional operating-system aggregate install count.
    #[serde(rename = "allInstalls", skip_serializing_if = "Option::is_none")]
    pub all_installs: Option<u32>,
    /// Optional latest severity value.
    #[serde(rename = "latestSeverity", skip_serializing_if = "Option::is_none")]
    pub latest_severity: Option<String>,
    /// Optional highest severity value.
    #[serde(rename = "highestSeverity", skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<String>,
    /// Optional average severity value.
    #[serde(rename = "averageSeverity", skip_serializing_if = "Option::is_none")]
    pub average_severity: Option<String>,
    /// Optional operating-system host count alias exposed by gvmd.
    #[serde(rename = "hostCount", skip_serializing_if = "Option::is_none")]
    pub host_count: Option<u32>,
    /// Optional operating-system host list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<AssetHost>,
}

/// Paginated generic asset list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenericAssetPage {
    /// Page items.
    pub data: Vec<GenericAsset>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Combined generic config representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenericConfig {
    /// Config identifier.
    pub id: String,
    /// Config name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Optional backend numeric type discriminator.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub config_type: Option<u32>,
    /// Optional backend usage-type discriminator.
    #[serde(rename = "usageType", skip_serializing_if = "Option::is_none")]
    pub usage_type: Option<String>,
    /// Whether the config is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the config is writable.
    pub writable: bool,
}

/// Paginated generic config list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenericConfigPage {
    /// Page items.
    pub data: Vec<GenericConfig>,
    /// Pagination metadata.
    pub pagination: Pagination,
}
