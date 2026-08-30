// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{CreateTargetRequest, ModifyTargetRequest, TargetListQuery, TargetResponse};
use gvm_gateway_domain::Target;

#[test]
fn target_list_query_decodes_filter_and_encoded_filter_id() {
    let parsed = TargetListQuery::try_from_query_string(
            "filter=severity%3E5+and+name~%22foo%20bar%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&per_page=50",
        )
        .expect("target query should parse");

    assert_eq!(
        parsed.filter_string.as_deref(),
        Some("severity>5 and name~\"foo bar\"")
    );
    assert_eq!(
        parsed.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(parsed.page, 1);
    assert_eq!(parsed.per_page, 50);
}

#[test]
fn target_response_preserves_unknown_alive_test() {
    let response = TargetResponse::from(Target {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Example".to_string(),
        comment: None,
        hosts: vec!["192.0.2.1".to_string()],
        exclude_hosts: vec![],
        alive_test: Some("Passive DNS".to_string()),
        port_list: None,
        reverse_lookup_only: false,
        reverse_lookup_unify: false,
        ssh_credential: None,
        smb_credential: None,
        esxi_credential: None,
        snmp_credential: None,
        in_use: false,
        writable: true,
    });

    let value = serde_json::to_value(response).expect("target response should serialize");
    assert_eq!(value["aliveTest"], json!("Passive DNS"));
}

#[test]
fn target_requests_reject_unknown_fields() {
    // Strict request DTOs make top-level target typos fail fast instead of
    // silently dropping fields like the issue's `portlistId` example.
    let error = serde_json::from_value::<CreateTargetRequest>(json!({
        "name": "Example",
        "hosts": ["192.0.2.1"],
        "portlistId": "123e4567-e89b-12d3-a456-426614174000"
    }))
    .expect_err("unknown create-target field should be rejected");
    assert!(
        error.to_string().contains("portlistId"),
        "error should name the rejected field: {error}"
    );

    let error = serde_json::from_value::<ModifyTargetRequest>(json!({
        "comment": "updated",
        "reverseLookupOnly": true,
        "reverseLookupOnlyy": false
    }))
    .expect_err("unknown update-target field should be rejected");
    assert!(
        error.to_string().contains("reverseLookupOnlyy"),
        "error should name the rejected field: {error}"
    );

    serde_json::from_value::<CreateTargetRequest>(json!({
        "name": "Example",
        "hosts": ["192.0.2.1"],
        "portListId": "123e4567-e89b-12d3-a456-426614174000"
    }))
    .expect("documented create-target fields should still parse");
}
