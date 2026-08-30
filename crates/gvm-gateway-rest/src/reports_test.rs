// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    GetReportQuery, ReportClosedCveListResponse, ReportErrorListResponse, ReportResultsQuery,
    ReportVulnerabilityListResponse,
};
use gvm_gateway_domain::{
    Pagination, ReportClosedCve, ReportClosedCvePage, ReportError, ReportErrorPage,
    ReportVulnerability, ReportVulnerabilityPage,
};

#[test]
fn report_queries_decode_pagination_and_filter_values() {
    let report = GetReportQuery::try_from_query_string("page=2&perPage=30")
        .expect("encoded report query should parse");
    assert_eq!(report.page, 2);
    assert_eq!(report.per_page, 30);

    let results = ReportResultsQuery::try_from_query_string(
            "filter=severity%3E5+and+location~%22host%26port%3D443%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&page=2&perPage=10",
        )
        .expect("encoded filter should parse");
    assert_eq!(
        results.filter_string.as_deref(),
        Some("severity>5 and location~\"host&port=443\"")
    );
    assert_eq!(
        results.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(results.page, 2);
    assert_eq!(results.per_page, 10);
}

#[test]
fn report_vulnerability_response_preserves_aggregate_fields() {
    // Vulnerability drill-downs are aggregate findings, not generic results;
    // the REST DTO must keep their count and NVT metadata shape intact.
    let json = serde_json::to_value(ReportVulnerabilityListResponse::from(
        ReportVulnerabilityPage {
            data: vec![ReportVulnerability {
                id: Some("row-1".to_string()),
                nvt: Some(gvm_gateway_domain::NvtRef {
                    oid: Some("1.3.6.1.4.1.25623.1.0.100000".to_string()),
                    name: Some("TLS finding".to_string()),
                    family: Some("General".to_string()),
                    cvss_base: None,
                    cves: vec!["CVE-2026-0001".to_string()],
                    tags: None,
                }),
                host: None,
                port: None,
                threat: Some("Medium".to_string()),
                severity: Some(5.0),
                hosts_count: Some(2),
                occurrences: Some(3),
            }],
            pagination: Pagination {
                page: 1,
                per_page: 25,
                total: 1,
                total_pages: 1,
            },
        },
    ))
    .expect("vulnerability response should serialize");

    assert_eq!(
        json["data"][0]["nvt"]["oid"],
        "1.3.6.1.4.1.25623.1.0.100000"
    );
    assert_eq!(json["data"][0]["threat"], "Medium");
    assert_eq!(json["data"][0]["hostsCount"], 2);
    assert_eq!(json["data"][0]["occurrences"], 3);
    assert!(json["data"][0].get("description").is_none());
}

#[test]
fn report_error_response_omits_fabricated_result_fields() {
    // Report-error rows must no longer inherit synthesized result threat or
    // severity fields from the generic result DTO.
    let json = serde_json::to_value(ReportErrorListResponse::from(ReportErrorPage {
        data: vec![ReportError {
            id: Some("row-2".to_string()),
            name: Some("VT error".to_string()),
            host: Some("192.0.2.10".to_string()),
            port: Some("443/tcp".to_string()),
            description: Some("scan failed".to_string()),
            nvt_name: Some("Broken VT".to_string()),
        }],
        pagination: Pagination {
            page: 1,
            per_page: 25,
            total: 1,
            total_pages: 1,
        },
    }))
    .expect("error response should serialize");

    assert_eq!(json["data"][0]["nvtName"], "Broken VT");
    assert!(json["data"][0].get("threat").is_none());
    assert!(json["data"][0].get("severity").is_none());
}

#[test]
fn report_closed_cve_response_preserves_closed_cve_fields() {
    // Closed-CVE drill-downs must expose the closed CVE id and backend threat
    // metadata without being coerced into the generic result `name` contract.
    let json = serde_json::to_value(ReportClosedCveListResponse::from(ReportClosedCvePage {
        data: vec![ReportClosedCve {
            id: Some("row-3".to_string()),
            nvt: Some(gvm_gateway_domain::NvtRef {
                oid: Some("1.3.6.1.4.1.25623.1.0.200000".to_string()),
                name: Some("Closed check".to_string()),
                family: None,
                cvss_base: None,
                cves: vec!["CVE-2025-9999".to_string()],
                tags: None,
            }),
            cve: Some("CVE-2025-9999".to_string()),
            host: Some("192.0.2.30".to_string()),
            severity: Some(5.0),
            threat: Some("Medium".to_string()),
        }],
        pagination: Pagination {
            page: 1,
            per_page: 25,
            total: 1,
            total_pages: 1,
        },
    }))
    .expect("closed-cve response should serialize");

    assert_eq!(json["data"][0]["cve"], "CVE-2025-9999");
    assert_eq!(json["data"][0]["threat"], "Medium");
    assert_eq!(json["data"][0]["nvt"]["name"], json!("Closed check"));
    assert!(json["data"][0].get("name").is_none());
}
