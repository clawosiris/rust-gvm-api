// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! GMP → domain type conversions, error mapping, and shared parsing helpers.
//!
//! Everything in this module is `pub(crate)` — it is an implementation detail
//! of the gvmd adapter and not part of the crate's public API.

use std::str::FromStr;

use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, NvtRef, Report, ResourceRef, ResultCount, ScanConfig,
    ScanResult, Scanner, Target, Task,
};
use gvm_gmp::{AliveTest, EntityId, HostsOrdering};

// ============================================================================
// GMP → Domain Conversion Utilities
// ============================================================================

pub(crate) fn target_from_gmp(target: gvm_gmp::responses::Target) -> Target {
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

pub(crate) fn task_from_gmp(task: gvm_gmp::responses::Task) -> Task {
    let named_entity_to_ref = |entity: gvm_gmp::responses::NamedEntity| -> ResourceRef {
        ResourceRef {
            id: entity.id.to_string(),
            name: if entity.name.is_empty() {
                None
            } else {
                Some(entity.name)
            },
        }
    };

    Task {
        id: task.meta.id.to_string(),
        name: task.meta.name,
        comment: task.meta.comment,
        status: task.status.unwrap_or_else(|| "New".to_string()),
        target: task.target.map(&named_entity_to_ref),
        scan_config: task.config.map(&named_entity_to_ref),
        scanner: task.scanner.map(&named_entity_to_ref),
        schedule: task.schedule.map(&named_entity_to_ref),
        alerts: task.alerts.into_iter().map(&named_entity_to_ref).collect(),
        alterable: None,
        hosts_ordering: task.hosts_ordering,
        observers: vec![],
        schedule_periods: None,
        last_report: task.last_report.map(|lr| ResourceRef {
            id: lr.id.to_string(),
            name: None,
        }),
        current_report: None,
        result_count: task.report_count,
        in_use: task.meta.in_use,
        writable: task.meta.writable,
    }
}

pub(crate) fn report_from_gmp(report: gvm_gmp::responses::Report) -> Report {
    let severity = report
        .severity
        .as_ref()
        .and_then(|s| s.full.as_deref())
        .and_then(|v| v.parse::<f64>().ok());

    Report {
        id: report.meta.id.to_string(),
        task: report.task.map(|t| ResourceRef {
            id: t.id.to_string(),
            name: Some(t.name),
        }),
        scan_start: report.scan_start,
        scan_end: report.scan_end,
        severity,
        result_count: report.result_count.map(|rc| ResultCount {
            total: rc.full,
            high: None,
            medium: None,
            low: None,
            log: None,
            false_positive: None,
        }),
        results: vec![],
    }
}

pub(crate) fn result_from_gmp(result: gvm_gmp::responses::ScanResult) -> ScanResult {
    let severity = result
        .severity
        .as_deref()
        .and_then(|v| v.parse::<f64>().ok());

    let nvt = result.nvt.map(|n| NvtRef {
        oid: Some(n.oid),
        name: n.name,
        family: n.family,
        cvss_base: n.cvss_base.as_deref().and_then(|v| v.parse::<f64>().ok()),
        cves: vec![],
        tags: None,
    });

    ScanResult {
        id: result.meta.id.to_string(),
        name: result.meta.name,
        host: result.host,
        port: result.port,
        severity,
        threat: result.threat,
        nvt,
        description: result.description,
        task: None,
        report: None,
    }
}

pub(crate) fn scan_config_from_gmp(config: gvm_gmp::responses::ScanConfig) -> ScanConfig {
    ScanConfig {
        id: config.meta.id.to_string(),
        name: config.meta.name,
        comment: config.meta.comment,
        family_count: None,
        nvt_count: None,
        config_type: None,
        in_use: config.meta.in_use,
        writable: config.meta.writable,
    }
}

pub(crate) fn scanner_from_gmp(scanner: gvm_gmp::responses::Scanner) -> Scanner {
    Scanner {
        id: scanner.meta.id.to_string(),
        name: scanner.meta.name,
        comment: scanner.meta.comment,
        host: scanner.host,
        port: scanner.port.map(|p| p as u32),
        scanner_type: scanner.scanner_type,
    }
}

// ============================================================================
// Shared Parsing / Validation Helpers
// ============================================================================

pub(crate) fn reject_unsupported_credentials(
    input: &CreateTargetInput,
) -> Result<(), GatewayError> {
    if input.ssh_credential_id.is_some()
        || input.smb_credential_id.is_some()
        || input.esxi_credential_id.is_some()
        || input.snmp_credential_id.is_some()
    {
        return Err(GatewayError::InvalidInput(
            "credential references are not supported by rust-gvm target commands yet".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_entity_id(value: &str) -> Result<EntityId, GatewayError> {
    EntityId::new(value).map_err(|_| GatewayError::InvalidInput(format!("invalid UUID: {value}")))
}

pub(crate) fn parse_alive_test(value: &str) -> Result<AliveTest, GatewayError> {
    AliveTest::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid aliveTest: {value}")))
}

pub(crate) fn parse_hosts_ordering(value: &str) -> Result<HostsOrdering, GatewayError> {
    match value {
        "sequential" => Ok(HostsOrdering::Sequential),
        "random" => Ok(HostsOrdering::Random),
        "reverse" => Ok(HostsOrdering::Reverse),
        _ => Err(GatewayError::InvalidInput(format!(
            "invalid hostsOrdering: {value}"
        ))),
    }
}

// ============================================================================
// Error Mapping
// ============================================================================

pub(crate) fn map_gvm_error(error: gvm_client::GvmError) -> GatewayError {
    match error {
        gvm_client::GvmError::Server {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_client::GvmError::Server {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        gvm_client::GvmError::Server {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_client::GvmError::Timeout(duration) => {
            GatewayError::BackendUnavailable(format!("gvmd timeout after {duration:?}"))
        }
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

pub(crate) fn map_parse_error(error: gvm_gmp::responses::ParseError) -> GatewayError {
    match error {
        gvm_gmp::responses::ParseError::ServerError {
            status: 404,
            message,
        } => GatewayError::NotFound(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message,
        } => GatewayError::InvalidInput(message),
        gvm_gmp::responses::ParseError::ServerError {
            status: 401,
            message,
        } => GatewayError::Unauthorized(message),
        other => GatewayError::BackendUnavailable(other.to_string()),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use gvm_gmp::responses::GetTargetsResponse;
    use gvm_protocol::Response as GmpResponse;

    #[test]
    fn parse_entity_id_valid() {
        let result = parse_entity_id("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_entity_id_invalid_empty() {
        let result = parse_entity_id("");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn parse_entity_id_invalid_special_chars() {
        let result = parse_entity_id("invalid@id");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn parse_alive_test_valid() {
        let result = parse_alive_test("ICMP Ping");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_alive_test_invalid() {
        let result = parse_alive_test("InvalidTest");
        assert!(matches!(result, Err(GatewayError::InvalidInput(_))));
    }

    #[test]
    fn reject_unsupported_credentials_passes_empty() {
        let input = CreateTargetInput {
            name: "test".to_string(),
            comment: None,
            hosts: vec!["127.0.0.1".to_string()],
            exclude_hosts: vec![],
            alive_test: None,
            port_list_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            ssh_credential_id: None,
            smb_credential_id: None,
            esxi_credential_id: None,
            snmp_credential_id: None,
        };
        assert!(reject_unsupported_credentials(&input).is_ok());
    }

    #[test]
    fn reject_unsupported_credentials_fails_ssh() {
        let input = CreateTargetInput {
            name: "test".to_string(),
            comment: None,
            hosts: vec!["127.0.0.1".to_string()],
            exclude_hosts: vec![],
            alive_test: None,
            port_list_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            ssh_credential_id: Some("cred-id".to_string()),
            smb_credential_id: None,
            esxi_credential_id: None,
            snmp_credential_id: None,
        };
        assert!(matches!(
            reject_unsupported_credentials(&input),
            Err(GatewayError::InvalidInput(_))
        ));
    }

    #[test]
    fn reject_unsupported_credentials_fails_smb() {
        let input = CreateTargetInput {
            name: "test".to_string(),
            comment: None,
            hosts: vec![],
            exclude_hosts: vec![],
            alive_test: None,
            port_list_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            ssh_credential_id: None,
            smb_credential_id: Some("cred-id".to_string()),
            esxi_credential_id: None,
            snmp_credential_id: None,
        };
        assert!(matches!(
            reject_unsupported_credentials(&input),
            Err(GatewayError::InvalidInput(_))
        ));
    }

    #[test]
    fn map_gvm_error_400_to_invalid_input() {
        let error = gvm_client::GvmError::Server {
            status: 400,
            message: "bad request".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::InvalidInput(_)));
    }

    #[test]
    fn map_gvm_error_401_to_unauthorized() {
        let error = gvm_client::GvmError::Server {
            status: 401,
            message: "unauthorized".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::Unauthorized(_)));
    }

    #[test]
    fn map_gvm_error_404_to_not_found() {
        let error = gvm_client::GvmError::Server {
            status: 404,
            message: "not found".to_string(),
        };
        let mapped = map_gvm_error(error);
        assert!(matches!(mapped, GatewayError::NotFound(_)));
    }

    #[test]
    fn map_parse_error_404_to_not_found() {
        let error = gvm_gmp::responses::ParseError::ServerError {
            status: 404,
            message: "not found".to_string(),
        };
        let mapped = map_parse_error(error);
        assert!(matches!(mapped, GatewayError::NotFound(_)));
    }

    #[test]
    fn map_parse_error_400_to_invalid_input() {
        let error = gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message: "bad request".to_string(),
        };
        let mapped = map_parse_error(error);
        assert!(matches!(mapped, GatewayError::InvalidInput(_)));
    }

    #[test]
    fn target_from_gmp_roundtrip() {
        let response = GmpResponse::from(
            r#"<get_targets_response status="200" status_text="OK">
            <target id="550e8400-e29b-41d4-a716-446655440000">
                <owner><name>admin</name></owner>
                <name>Example Target</name>
                <comment>demo</comment>
                <creation_time>2026-03-27T00:00:00Z</creation_time>
                <modification_time>2026-03-27T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>0</in_use>
                <hosts>10.0.0.1,10.0.0.2</hosts>
                <exclude_hosts>10.0.0.3</exclude_hosts>
                <alive_tests>ICMP Ping</alive_tests>
                <reverse_lookup_only>1</reverse_lookup_only>
                <reverse_lookup_unify>0</reverse_lookup_unify>
                <port_list id="11111111-1111-1111-1111-111111111111"><name>All TCP</name></port_list>
            </target>
        </get_targets_response>"#,
        );
        let parsed = GetTargetsResponse::from_response(&response).unwrap();

        let target = target_from_gmp(parsed.items.into_iter().next().unwrap());

        assert_eq!(target.id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(target.name, "Example Target");
        assert_eq!(target.comment.as_deref(), Some("demo"));
        assert_eq!(target.hosts, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(target.exclude_hosts, vec!["10.0.0.3"]);
        assert_eq!(target.alive_test.as_deref(), Some("ICMP Ping"));
        assert!(target.reverse_lookup_only);
        assert!(!target.reverse_lookup_unify);
        assert_eq!(target.port_list.unwrap().name.as_deref(), Some("All TCP"));
    }
}
