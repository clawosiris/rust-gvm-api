// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::ScannerResponse;
use gvm_gateway_domain::{ResourceRef, Scanner};

#[test]
fn scanner_response_preserves_unknown_type() {
    let response = ScannerResponse::from(Scanner {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Custom".to_string(),
        comment: None,
        host: None,
        port: None,
        scanner_type: Some("Sensor".to_string()),
        credential: None,
        ca_pub: None,
        in_use: false,
        writable: true,
    });

    let value = serde_json::to_value(response).expect("scanner response should serialize");
    assert_eq!(value["type"], json!("Sensor"));
}

#[test]
fn scanner_response_preserves_typed_metadata_fields() {
    // Scanner reads must expose typed credential and write-state metadata
    // now that rust-gvm parses those fields from gvmd responses.
    let response = ScannerResponse::from(Scanner {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "OSP Scanner".to_string(),
        comment: Some("primary".to_string()),
        host: Some("127.0.0.1".to_string()),
        port: Some(9390),
        scanner_type: Some("OSP".to_string()),
        credential: Some(ResourceRef {
            id: "11111111-1111-1111-1111-111111111111".to_string(),
            name: Some("Scanner Credential".to_string()),
        }),
        ca_pub: Some("CA certificate".to_string()),
        in_use: true,
        writable: false,
    });

    let value = serde_json::to_value(response).expect("scanner response should serialize");

    assert_eq!(
        value["credential"]["id"],
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(value["credential"]["name"], "Scanner Credential");
    assert_eq!(value["caPub"], "CA certificate");
    assert_eq!(value["inUse"], true);
    assert_eq!(value["writable"], false);
}
