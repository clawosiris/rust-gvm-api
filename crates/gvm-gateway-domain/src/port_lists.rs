// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port-list domain types and commands.

use serde::{Deserialize, Serialize};

use crate::Pagination;

/// Domain port-list representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortList {
    /// Port-list identifier.
    pub id: String,
    /// Port-list name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional aggregate port count.
    #[serde(rename = "portCount")]
    pub port_count: Option<u32>,
    /// Optional TCP port count.
    #[serde(rename = "tcpCount")]
    pub tcp_count: Option<u32>,
    /// Optional UDP port count.
    #[serde(rename = "udpCount")]
    pub udp_count: Option<u32>,
    /// Optional raw range string.
    #[serde(rename = "portRange")]
    pub port_range: Option<String>,
    /// Whether the port list is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the port list is writable.
    pub writable: bool,
}

/// Paginated port-list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortListPage {
    /// Page items.
    pub data: Vec<PortList>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Port-list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortListQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Port-list create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatePortListInput {
    /// Port-list name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional raw port-range expression.
    pub port_range: Option<String>,
}

/// Port-list update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyPortListInput {
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional raw port-range expression.
    pub port_range: Option<String>,
}
