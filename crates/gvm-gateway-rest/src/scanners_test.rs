// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::ScannerResponse;
use gvm_gateway_domain::Scanner;

#[test]
fn scanner_response_preserves_unknown_type() {
    let response = ScannerResponse::from(Scanner {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Custom".to_string(),
        comment: None,
        host: None,
        port: None,
        scanner_type: Some("Sensor".to_string()),
    });

    let value = serde_json::to_value(response).expect("scanner response should serialize");
    assert_eq!(value["type"], json!("Sensor"));
}
