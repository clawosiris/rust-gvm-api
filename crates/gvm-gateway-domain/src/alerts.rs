// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Alert domain types and commands.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Domain alert representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Alert {
    /// Alert identifier.
    pub id: String,
    /// Alert name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Alert event selector.
    pub event: Option<String>,
    /// Alert condition selector.
    pub condition: Option<String>,
    /// Alert delivery method.
    pub method: Option<String>,
    /// Optional event data map.
    pub event_data: HashMap<String, String>,
    /// Optional condition data map.
    pub condition_data: HashMap<String, String>,
    /// Optional method data map.
    pub method_data: HashMap<String, String>,
    /// Optional filter reference.
    pub filter: Option<ResourceRef>,
    /// Whether the alert is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the alert is writable.
    pub writable: bool,
}

/// Paginated alert list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlertPage {
    /// Page items.
    pub data: Vec<Alert>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Alert list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AlertQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Alert create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateAlertInput {
    /// Alert name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional event.
    pub event: Option<String>,
    /// Optional condition.
    pub condition: Option<String>,
    /// Optional method.
    pub method: Option<String>,
    /// Optional event data map.
    pub event_data: HashMap<String, String>,
    /// Optional condition data map.
    pub condition_data: HashMap<String, String>,
    /// Optional method data map.
    pub method_data: HashMap<String, String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
}

/// Alert update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyAlertInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional event.
    pub event: Option<String>,
    /// Optional condition.
    pub condition: Option<String>,
    /// Optional method.
    pub method: Option<String>,
    /// Optional event data map.
    pub event_data: Option<HashMap<String, String>>,
    /// Optional condition data map.
    pub condition_data: Option<HashMap<String, String>>,
    /// Optional method data map.
    pub method_data: Option<HashMap<String, String>>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
}
