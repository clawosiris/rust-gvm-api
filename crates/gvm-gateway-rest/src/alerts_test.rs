// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::collections::HashMap;

use serde_json::json;

use super::{AlertCondition, AlertEvent, AlertMethod, AlertResponse};
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
