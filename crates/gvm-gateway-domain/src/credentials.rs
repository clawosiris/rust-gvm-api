// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Credential domain types and commands.

use serde::{Deserialize, Serialize};

use crate::Pagination;

/// Domain credential representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credential {
    /// Credential identifier.
    pub id: String,
    /// Credential name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional type code.
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    /// Optional login value.
    pub login: Option<String>,
    /// Whether the credential is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the credential is writable.
    pub writable: bool,
}

/// Paginated credential list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialPage {
    /// Page items.
    pub data: Vec<Credential>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Credential list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Credential create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreateCredentialInput {
    /// Credential name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Credential type code.
    pub credential_type: String,
    /// Optional login value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key.
    pub private_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community.
    pub community: Option<String>,
    /// Optional SNMP auth algorithm.
    pub auth_algorithm: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<String>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
}

/// Credential update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyCredentialInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional login value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key.
    pub private_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community.
    pub community: Option<String>,
    /// Optional SNMP auth algorithm.
    pub auth_algorithm: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<String>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
}
