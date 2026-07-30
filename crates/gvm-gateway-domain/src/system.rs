// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System-facing DTOs.

use serde::{Deserialize, Serialize};

/// Liveness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthStatus {
    /// Liveness state.
    pub status: &'static str,
}

/// Readiness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessStatus {
    /// Readiness state.
    pub status: &'static str,
    /// Optional reason when not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// API and GMP version information.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    /// Gateway API version.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// GMP backend version.
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

/// Query options for the aggregates endpoint.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AggregatesQuery {
    /// Required backend resource type to aggregate over (e.g. `nvt`, `task`, `result`).
    pub resource_type: String,
    /// Optional group-by column.
    pub group_column: Option<String>,
    /// Optional comma-separated data columns.
    pub data_columns: Option<String>,
    /// Optional inline filter expression.
    pub filter: Option<String>,
}

/// A single aggregate subgroup value/count pair.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AggregateSubgroup {
    /// Subgroup value.
    pub value: String,
    /// Subgroup count.
    pub count: u32,
}

/// A single aggregate group with its count and optional nested subgroups.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AggregateGroup {
    /// Group value.
    pub value: String,
    /// Group count.
    pub count: u32,
    /// Optional cumulative count.
    #[serde(rename = "cCount", skip_serializing_if = "Option::is_none")]
    pub c_count: Option<u32>,
    /// Optional group text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Nested subgroups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subgroups: Vec<AggregateSubgroup>,
}

/// Overall aggregate statistics across all groups.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AggregateStats {
    /// Column the statistics apply to.
    pub column: String,
    /// Minimum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// Maximum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Mean value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean: Option<f64>,
    /// Sum of values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sum: Option<f64>,
}

/// Aggregate query result.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Aggregates {
    /// Aggregate groups.
    pub groups: Vec<AggregateGroup>,
    /// Column info labels returned by the backend.
    #[serde(rename = "columnInfo", default, skip_serializing_if = "Vec::is_empty")]
    pub column_info: Vec<String>,
    /// Overall statistics when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall: Option<AggregateStats>,
}
