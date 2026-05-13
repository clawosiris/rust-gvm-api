// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Task domain types and commands.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Domain task representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Task {
    /// Task identifier.
    pub id: String,
    /// Task name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Task status.
    pub status: String,
    /// Target reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<ResourceRef>,
    /// Scan configuration reference.
    #[serde(rename = "scanConfig", skip_serializing_if = "Option::is_none")]
    pub scan_config: Option<ResourceRef>,
    /// Scanner reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner: Option<ResourceRef>,
    /// Schedule reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ResourceRef>,
    /// Alert references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<ResourceRef>,
    /// Whether the task is alterable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alterable: Option<bool>,
    /// Hosts ordering strategy.
    #[serde(rename = "hostsOrdering", skip_serializing_if = "Option::is_none")]
    pub hosts_ordering: Option<String>,
    /// Observer user names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observers: Vec<String>,
    /// Number of schedule periods.
    #[serde(rename = "schedulePeriods", skip_serializing_if = "Option::is_none")]
    pub schedule_periods: Option<u32>,
    /// Last report reference.
    #[serde(rename = "lastReport", skip_serializing_if = "Option::is_none")]
    pub last_report: Option<ResourceRef>,
    /// Current (in-progress) report reference.
    #[serde(rename = "currentReport", skip_serializing_if = "Option::is_none")]
    pub current_report: Option<ResourceRef>,
    /// Number of reports/results.
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    pub result_count: Option<u32>,
    /// Whether the task is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the task is writable.
    pub writable: bool,
}

/// Paginated task list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskPage {
    /// Page items.
    pub data: Vec<Task>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Task list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Task create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTaskInput {
    /// Task name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Target identifier (required).
    pub target_id: String,
    /// Scan config identifier (required).
    pub scan_config_id: String,
    /// Scanner identifier (required).
    pub scanner_id: String,
    /// Optional schedule identifier.
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    pub alert_ids: Vec<String>,
    /// Optional alterable flag.
    pub alterable: Option<bool>,
    /// Optional hosts ordering.
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    pub observers: Vec<String>,
    /// Optional schedule periods.
    pub schedule_periods: Option<u32>,
    /// Optional key-value scan preferences.
    pub preferences: Vec<(String, String)>,
}

/// Task update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyTaskInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional target identifier.
    pub target_id: Option<String>,
    /// Optional scan config identifier.
    pub scan_config_id: Option<String>,
    /// Optional scanner identifier.
    pub scanner_id: Option<String>,
    /// Optional schedule identifier.
    pub schedule_id: Option<String>,
    /// Optional alert identifiers.
    pub alert_ids: Option<Vec<String>>,
    /// Optional hosts ordering.
    pub hosts_ordering: Option<String>,
    /// Optional observers.
    pub observers: Vec<String>,
    /// Optional schedule periods.
    pub schedule_periods: Option<u32>,
}

/// Result from a start or resume task action containing the report identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskAction {
    /// UUID of the report created by the action.
    #[serde(rename = "reportId")]
    pub report_id: String,
}
