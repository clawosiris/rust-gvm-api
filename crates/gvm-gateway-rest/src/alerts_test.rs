// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::collections::HashMap;

use serde_json::json;

use super::{
    AlertCondition, AlertEvent, AlertMethod, AlertResponse, CreateAlertRequest, ModifyAlertRequest,
};
use gvm_gateway_domain::Alert;

fn alert_with_selectors(event: &str, condition: &str, method: &str) -> Alert {
    Alert {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Alert".to_string(),
        comment: None,
        event: Some(event.to_string()),
        condition: Some(condition.to_string()),
        method: Some(method.to_string()),
        event_data: HashMap::new(),
        condition_data: HashMap::new(),
        method_data: HashMap::new(),
        filter: None,
        in_use: false,
        writable: true,
    }
}

#[test]
fn alert_selector_deserialization_preserves_unknown_values() {
    // Alert selector vocabularies are owned by gvmd/rust-gvm. The REST
    // response wrapper must keep unknown future values intact.
    let event: AlertEvent =
        serde_json::from_value(json!("future_event")).expect("event should parse");
    let condition: AlertCondition =
        serde_json::from_value(json!("future_condition")).expect("condition should parse");
    let method: AlertMethod =
        serde_json::from_value(json!("future_method")).expect("method should parse");

    assert_eq!(serde_json::to_value(event).unwrap(), json!("future_event"));
    assert_eq!(
        serde_json::to_value(condition).unwrap(),
        json!("future_condition")
    );
    assert_eq!(
        serde_json::to_value(method).unwrap(),
        json!("future_method")
    );
}

#[test]
fn alert_response_preserves_known_and_unknown_selectors() {
    // Response conversion should not collapse alert selectors that are not
    // yet known to this gateway build.
    let known = serde_json::to_value(AlertResponse::from(alert_with_selectors(
        "task_run_status_changed",
        "always",
        "email",
    )))
    .expect("alert response should serialize");
    let unknown = serde_json::to_value(AlertResponse::from(alert_with_selectors(
        "future_event",
        "future_condition",
        "future_method",
    )))
    .expect("alert response should serialize");

    assert_eq!(known["event"], json!("task_run_status_changed"));
    assert_eq!(known["condition"], json!("always"));
    assert_eq!(known["method"], json!("email"));
    assert_eq!(unknown["event"], json!("future_event"));
    assert_eq!(unknown["condition"], json!("future_condition"));
    assert_eq!(unknown["method"], json!("future_method"));
}

#[test]
fn alert_requests_preserve_selector_data_maps_and_rename() {
    // Regression coverage for #402 and #404: alert create/modify requests must
    // keep the advertised selector data maps and replacement name intact.
    let create = CreateAlertRequest {
        name: "Alert".to_string(),
        comment: None,
        event: Some(AlertEvent::parse("task_run_status_changed")),
        condition: Some(AlertCondition::parse("severity_at_least")),
        method: Some(AlertMethod::parse("email")),
        event_data: HashMap::from([("status".to_string(), "Done".to_string())]),
        condition_data: HashMap::from([("severity".to_string(), "7.5".to_string())]),
        method_data: HashMap::from([("to_address".to_string(), "ops@example.com".to_string())]),
        filter_id: None,
    }
    .validate()
    .expect("alert create request should accept selector data maps");
    let modify = ModifyAlertRequest {
        name: Some("Renamed Alert".to_string()),
        comment: None,
        event: Some("task_run_status_changed".to_string()),
        condition: Some("severity_at_least".to_string()),
        method: Some("email".to_string()),
        event_data: Some(HashMap::from([(
            "status".to_string(),
            "Stopped".to_string(),
        )])),
        condition_data: Some(HashMap::from([("severity".to_string(), "8.0".to_string())])),
        method_data: Some(HashMap::from([(
            "to_address".to_string(),
            "soc@example.com".to_string(),
        )])),
        filter_id: None,
    }
    .validate()
    .expect("alert modify request should accept rename and selector data maps");

    assert_eq!(
        create.event_data.get("status").map(String::as_str),
        Some("Done")
    );
    assert_eq!(
        create.condition_data.get("severity").map(String::as_str),
        Some("7.5")
    );
    assert_eq!(
        create.method_data.get("to_address").map(String::as_str),
        Some("ops@example.com")
    );
    assert_eq!(modify.name.as_deref(), Some("Renamed Alert"));
    assert_eq!(
        modify
            .event_data
            .as_ref()
            .and_then(|data| data.get("status"))
            .map(String::as_str),
        Some("Stopped")
    );
    assert_eq!(
        modify
            .condition_data
            .as_ref()
            .and_then(|data| data.get("severity"))
            .map(String::as_str),
        Some("8.0")
    );
    assert_eq!(
        modify
            .method_data
            .as_ref()
            .and_then(|data| data.get("to_address"))
            .map(String::as_str),
        Some("soc@example.com")
    );
}

#[test]
fn alert_requests_reject_unknown_fields_but_keep_data_maps_open() {
    // Alert selector data maps are intentional extension points, but misspelled
    // top-level fields must now fail fast instead of being ignored.
    let error = serde_json::from_value::<ModifyAlertRequest>(json!({
        "eventData": {
            "recipient": "ops@example.com"
        },
        "eventdata": {
            "recipient": "typo@example.com"
        }
    }))
    .expect_err("unknown alert field should be rejected");
    assert!(
        error.to_string().contains("eventdata"),
        "error should name the rejected field: {error}"
    );

    serde_json::from_value::<CreateAlertRequest>(json!({
        "name": "Alert",
        "event": "task_run_status_changed",
        "condition": "always",
        "method": "email",
        "eventData": {
            "x-gvmd-event-key": "task-finished"
        },
        "conditionData": {
            "x-gvmd-condition-key": "high"
        },
        "methodData": {
            "to": "ops@example.com",
            "x-gvmd-method-key": "extended"
        }
    }))
    .expect("documented alert fields and open data-map keys should still parse");
}
