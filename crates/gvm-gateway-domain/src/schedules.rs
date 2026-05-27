// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Schedule domain types and commands.

use serde::{Deserialize, Serialize};

use crate::Pagination;

/// Domain schedule representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Schedule {
    /// Schedule identifier.
    pub id: String,
    /// Schedule name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional iCalendar rule definition.
    pub icalendar: Option<String>,
    /// Optional timezone.
    pub timezone: Option<String>,
    /// Optional first run timestamp.
    #[serde(rename = "firstRun")]
    pub first_run: Option<String>,
    /// Optional next run timestamp.
    #[serde(rename = "nextRun")]
    pub next_run: Option<String>,
    /// Optional max duration in seconds.
    pub duration: Option<u32>,
    /// Whether the schedule is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the schedule is writable.
    pub writable: bool,
}

/// Paginated schedule list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulePage {
    /// Page items.
    pub data: Vec<Schedule>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Supported backend timezone identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Timezone {
    /// IANA timezone identifier.
    pub name: String,
    /// Optional human-friendly label.
    pub display_name: Option<String>,
}

/// Schedule list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScheduleQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Schedule create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateScheduleInput {
    /// Schedule name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// RFC5545 calendar definition.
    pub icalendar: String,
    /// Timezone identifier.
    pub timezone: String,
}

/// Schedule update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyScheduleInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional RFC5545 calendar definition.
    pub icalendar: Option<String>,
    /// Optional timezone identifier.
    pub timezone: Option<String>,
}
