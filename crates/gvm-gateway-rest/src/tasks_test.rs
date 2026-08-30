// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{ModifyTaskRequest, TaskResponse};
use gvm_gateway_domain::{
    ResourceRef, Task, TaskObservers, TaskReportComplianceCount, TaskReportReference,
    TaskReportResultCount,
};

fn task_with_status(status: &str) -> Task {
    Task {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Example".to_string(),
        comment: None,
        status: status.to_string(),
        progress: Some(42),
        target: None,
        scan_config: None,
        scanner: None,
        schedule: None,
        alerts: vec![],
        alterable: None,
        hosts_ordering: None,
        observers: TaskObservers::default(),
        schedule_periods: None,
        last_report: None,
        current_report: None,
        report_count: Some(3),
        usage_type: None,
        trend: None,
        in_use: false,
        writable: true,
    }
}

#[test]
fn task_response_preserves_unknown_hosts_ordering() {
    let response = TaskResponse::from(Task {
        hosts_ordering: Some("by-latency".to_string()),
        ..task_with_status("Running")
    });

    let value = serde_json::to_value(response).expect("task response should serialize");
    assert_eq!(value["hostsOrdering"], json!("by-latency"));
}

#[test]
fn task_response_preserves_live_gvmd_status_values() {
    // Live task lifecycle values must remain visible to clients rather
    // than being coerced to an older enum variant.
    for status in [
        "New",
        "Requested",
        "Queued",
        "Running",
        "Stop Requested",
        "Stopping",
        "Processing",
        "Done",
        "Stopped",
        "Error",
        "Delete Requested",
        "Ultimate Delete Requested",
        "Container",
        "Interrupted",
    ] {
        let json = serde_json::to_value(TaskResponse::from(task_with_status(status))).unwrap();

        assert_eq!(json["status"], status);
    }
}

#[test]
fn task_response_preserves_unknown_status_and_report_count_semantics() {
    // Unknown future gvmd statuses should still be round-tripped, and the
    // count field must be named for the report-count source data.
    let json = serde_json::to_value(TaskResponse::from(task_with_status("Future State"))).unwrap();

    assert_eq!(json["status"], "Future State");
    assert_eq!(json["progress"], 42);
    assert_eq!(json["reportCount"], 3);
    assert!(json.get("resultCount").is_none());
}

#[test]
fn task_response_preserves_group_and_role_observers() {
    // Task observers can be non-user principals; those must not disappear
    // when gvmd reports a group-only or role-only observer shape.
    let response = TaskResponse::from(Task {
        observers: TaskObservers {
            users: vec![],
            groups: vec![ResourceRef {
                id: "11111111-1111-1111-1111-111111111111".to_string(),
                name: Some("Auditors".to_string()),
            }],
            roles: vec![ResourceRef {
                id: "22222222-2222-2222-2222-222222222222".to_string(),
                name: Some("Observers".to_string()),
            }],
        },
        ..task_with_status("Running")
    });

    let json = serde_json::to_value(response).unwrap();

    assert!(json["observers"].get("users").is_none());
    assert_eq!(json["observers"]["groups"][0]["name"], "Auditors");
    assert_eq!(json["observers"]["roles"][0]["name"], "Observers");
}

#[test]
fn modify_task_request_forwards_alterable() {
    // Regression coverage for #406: PUT /tasks/{id} must expose the same
    // alterable control as task creation and preserve an explicit false value.
    let request: ModifyTaskRequest = serde_json::from_value(json!({ "alterable": false }))
        .expect("alterable should deserialize on task modify");

    let input = request
        .validate()
        .expect("alterable requires no ID validation");

    assert_eq!(input.alterable, Some(false));
}

#[test]
fn task_response_preserves_report_reference_metadata_and_usage_fields() {
    // Task reads must expose typed report summaries, usageType, and trend
    // instead of dropping that gvmd metadata at the REST boundary.
    let response = TaskResponse::from(Task {
        last_report: Some(TaskReportReference {
            id: "33333333-3333-3333-3333-333333333333".to_string(),
            timestamp: Some("2026-08-28T12:00:00Z".to_string()),
            scan_start: Some("2026-08-28T11:30:00Z".to_string()),
            scan_end: Some("2026-08-28T11:59:00Z".to_string()),
            result_count: Some(TaskReportResultCount {
                critical: Some(1),
                high: Some(2),
                medium: Some(3),
                low: Some(4),
                log: Some(5),
                false_positive: Some(6),
            }),
            severity: Some("8.8".to_string()),
            compliance_count: Some(TaskReportComplianceCount {
                yes: Some(7),
                no: Some(8),
                incomplete: Some(9),
            }),
        }),
        current_report: Some(TaskReportReference {
            id: "44444444-4444-4444-4444-444444444444".to_string(),
            timestamp: Some("2026-08-28T12:10:00Z".to_string()),
            scan_start: Some("2026-08-28T12:05:00Z".to_string()),
            scan_end: None,
            result_count: None,
            severity: None,
            compliance_count: None,
        }),
        usage_type: Some("audit".to_string()),
        trend: Some("up".to_string()),
        ..task_with_status("Done")
    });

    let json = serde_json::to_value(response).expect("task response should serialize");

    assert_eq!(json["usageType"], "audit");
    assert_eq!(json["trend"], "up");
    assert_eq!(
        json["lastReport"]["timestamp"],
        json!("2026-08-28T12:00:00Z")
    );
    assert_eq!(json["lastReport"]["resultCount"]["critical"], 1);
    assert_eq!(json["lastReport"]["resultCount"]["falsePositive"], 6);
    assert_eq!(json["lastReport"]["severity"], "8.8");
    assert_eq!(json["lastReport"]["complianceCount"]["yes"], 7);
    assert_eq!(json["currentReport"]["scanStart"], "2026-08-28T12:05:00Z");
    assert!(json["currentReport"].get("severity").is_none());
}
