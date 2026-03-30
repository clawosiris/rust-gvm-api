// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Target request parsing and response mapping for the REST adapter.

use gvm_gateway_domain::{CreateTargetInput, GatewayError, ModifyTargetInput, ResourceRef, Target};
use gvm_gmp::responses::Target as GmpTarget;
use serde::Deserialize;
use uuid::Uuid;

/// Parsed list-targets query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl TargetListQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut filter_string = None;
        let mut filter_id = None;
        let mut page = None;
        let mut per_page = None;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                "filter" => filter_string = Some(value.to_string()),
                "filterId" => {
                    validate_uuid("filterId", value)?;
                    filter_id = Some(value.to_string());
                }
                "page" => {
                    page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("page must be a positive integer".to_string())
                    })?);
                }
                "perPage" | "per_page" => {
                    per_page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                    })?);
                }
                _ => {}
            }
        }

        let page = page.unwrap_or(1);
        if page == 0 {
            return Err(GatewayError::InvalidInput(
                "page must be greater than or equal to 1".to_string(),
            ));
        }

        let per_page = per_page.unwrap_or(25).clamp(1, 1000);

        Ok(Self {
            filter_string,
            filter_id,
            page,
            per_page,
        })
    }
}

/// Create-target request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CreateTargetRequest {
    /// Optional name so validation can return RFC 9457 instead of extractor failures.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Excluded hosts.
    #[serde(rename = "excludeHosts", default)]
    pub exclude_hosts: Vec<String>,
    /// Optional alive test.
    #[serde(rename = "aliveTest")]
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    #[serde(rename = "portListId")]
    pub port_list_id: Option<String>,
    /// Reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: Option<bool>,
    /// Reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier.
    #[serde(rename = "sshCredentialId")]
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier.
    #[serde(rename = "smbCredentialId")]
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier.
    #[serde(rename = "esxiCredentialId")]
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier.
    #[serde(rename = "snmpCredentialId")]
    pub snmp_credential_id: Option<String>,
}

impl CreateTargetRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<CreateTargetInput, GatewayError> {
        let name = self
            .name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        if self.hosts.is_empty() {
            return Err(GatewayError::InvalidInput(
                "hosts must contain at least one entry".to_string(),
            ));
        }
        validate_optional_uuid("portListId", self.port_list_id.as_deref())?;
        validate_optional_uuid("sshCredentialId", self.ssh_credential_id.as_deref())?;
        validate_optional_uuid("smbCredentialId", self.smb_credential_id.as_deref())?;
        validate_optional_uuid("esxiCredentialId", self.esxi_credential_id.as_deref())?;
        validate_optional_uuid("snmpCredentialId", self.snmp_credential_id.as_deref())?;

        Ok(CreateTargetInput {
            name,
            comment: self.comment,
            hosts: self.hosts,
            exclude_hosts: self.exclude_hosts,
            alive_test: self.alive_test,
            port_list_id: self.port_list_id,
            reverse_lookup_only: self.reverse_lookup_only,
            reverse_lookup_unify: self.reverse_lookup_unify,
            ssh_credential_id: self.ssh_credential_id,
            smb_credential_id: self.smb_credential_id,
            esxi_credential_id: self.esxi_credential_id,
            snmp_credential_id: self.snmp_credential_id,
        })
    }
}

/// Modify-target request payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModifyTargetRequest {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional hosts.
    pub hosts: Option<Vec<String>>,
    /// Optional excluded hosts.
    #[serde(rename = "excludeHosts")]
    pub exclude_hosts: Option<Vec<String>>,
    /// Optional alive test.
    #[serde(rename = "aliveTest")]
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    #[serde(rename = "portListId")]
    pub port_list_id: Option<String>,
}

impl ModifyTargetRequest {
    /// Validate the request and convert it into the application command.
    pub fn validate(self) -> Result<ModifyTargetInput, GatewayError> {
        validate_optional_uuid("portListId", self.port_list_id.as_deref())?;

        Ok(ModifyTargetInput {
            name: self.name,
            comment: self.comment,
            hosts: self.hosts,
            exclude_hosts: self.exclude_hosts,
            alive_test: self.alive_test,
            port_list_id: self.port_list_id,
        })
    }
}

/// Build the GMP inline filter string.
pub fn build_gmp_filter(
    filter_string: Option<String>,
    _filter_id: Option<String>,
) -> Option<String> {
    filter_string.filter(|value| !value.trim().is_empty())
}

/// Convert a typed rust-gvm target into the REST response shape.
pub fn target_from_gmp(target: GmpTarget) -> Target {
    Target {
        id: target.meta.id.to_string(),
        name: target.meta.name,
        comment: target.meta.comment,
        hosts: target.hosts,
        exclude_hosts: target.exclude_hosts,
        alive_test: target.alive_tests,
        port_list: target.port_list.map(|resource| ResourceRef {
            id: resource.id.to_string(),
            name: Some(resource.name),
        }),
        reverse_lookup_only: target.reverse_lookup_only,
        reverse_lookup_unify: target.reverse_lookup_unify,
        ssh_credential: None,
        smb_credential: None,
        esxi_credential: None,
        snmp_credential: None,
        in_use: target.meta.in_use,
        writable: target.meta.writable,
    }
}

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

/// Validate a UUID-like REST resource identifier.
pub fn validate_uuid(field: &str, value: &str) -> Result<(), GatewayError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| GatewayError::InvalidInput(format!("{field} must be a valid UUID")))
}
