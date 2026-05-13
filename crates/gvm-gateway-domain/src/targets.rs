// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Target domain types and commands.

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Domain target representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Target {
    /// Target identifier.
    pub id: String,
    /// Target name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    #[serde(
        rename = "excludeHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude_hosts: Vec<String>,
    /// Optional alive-test strategy.
    #[serde(rename = "aliveTest", skip_serializing_if = "Option::is_none")]
    pub alive_test: Option<String>,
    /// Optional port list reference.
    #[serde(rename = "portList", skip_serializing_if = "Option::is_none")]
    pub port_list: Option<ResourceRef>,
    /// Reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: bool,
    /// Reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: bool,
    /// Optional SSH credential reference.
    #[serde(rename = "sshCredential", skip_serializing_if = "Option::is_none")]
    pub ssh_credential: Option<ResourceRef>,
    /// Optional SMB credential reference.
    #[serde(rename = "smbCredential", skip_serializing_if = "Option::is_none")]
    pub smb_credential: Option<ResourceRef>,
    /// Optional ESXi credential reference.
    #[serde(rename = "esxiCredential", skip_serializing_if = "Option::is_none")]
    pub esxi_credential: Option<ResourceRef>,
    /// Optional SNMP credential reference.
    #[serde(rename = "snmpCredential", skip_serializing_if = "Option::is_none")]
    pub snmp_credential: Option<ResourceRef>,
    /// Whether the target is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the target is writable.
    pub writable: bool,
}

/// Paginated target list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetPage {
    /// Page items.
    pub data: Vec<Target>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Target list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Target create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTargetInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    pub exclude_hosts: Vec<String>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
    /// Optional reverse lookup only.
    pub reverse_lookup_only: Option<bool>,
    /// Optional reverse lookup unify.
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier.
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<String>,
}

/// Target update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyTargetInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional hosts.
    pub hosts: Option<Vec<String>>,
    /// Optional excluded hosts.
    pub exclude_hosts: Option<Vec<String>>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
}
