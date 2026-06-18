// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{PaginationOnlyQuery, SupportingListQuery, TicketResponse, TicketStatus};
use crate::query::parse_delete_resource_query;
use gvm_gateway_domain::{SupportingResourceMeta, Ticket};

#[test]
fn supporting_query_decodes_percent_encoded_filter_values() {
    let parsed = SupportingListQuery::try_from_query_string(
        "filter=name~webserver%20and%20severity%3E5&perPage=10&page=2",
    )
    .expect("supporting-resource query should parse");

    assert_eq!(
        parsed.filter_string.as_deref(),
        Some("name~webserver and severity>5")
    );
    assert_eq!(parsed.page, 2);
    assert_eq!(parsed.per_page, 10);
}

#[test]
fn supporting_query_rejects_zero_page_after_decoding() {
    let error = SupportingListQuery::try_from_query_string("page=0")
        .expect_err("page=0 should remain invalid");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "page must be greater than or equal to 1");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn pagination_only_query_rejects_filter_params() {
    let error = PaginationOnlyQuery::try_from_query_string("filter=name~general")
        .expect_err("filter should be rejected");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "filter is not supported on this endpoint");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

#[test]
fn delete_supporting_resource_query_rejects_invalid_bool() {
    let error = parse_delete_resource_query("ultimate=not-bool")
        .expect_err("invalid ultimate bool should be rejected");

    match error {
        gvm_gateway_domain::GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "ultimate must be true or false");
        }
        other => panic!("unexpected error variant: {:?}", other),
    }
}

fn ticket_with_status(status: &str) -> Ticket {
    Ticket {
        meta: SupportingResourceMeta {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "Ticket".to_string(),
            comment: None,
            creation_time: None,
            modification_time: None,
            writable: true,
            in_use: false,
        },
        status: Some(status.to_string()),
        assigned_to: None,
        result: None,
        task: None,
        open_note: None,
        fixed_note: None,
        closed_note: None,
    }
}

#[test]
fn ticket_status_deserialization_preserves_unknown_values() {
    // Ticket status responses should preserve backend-added states even
    // when this gateway build only documents the current rust-gvm set.
    let parsed: TicketStatus =
        serde_json::from_value(json!("Deferred")).expect("ticket status should parse");

    assert_eq!(serde_json::to_value(parsed).unwrap(), json!("Deferred"));
}

#[test]
fn ticket_response_preserves_known_and_unknown_statuses() {
    // Current gvmd responses use display-case ticket statuses; future
    // values should remain visible to clients without coercion.
    let known = serde_json::to_value(TicketResponse::from(ticket_with_status("Open")))
        .expect("ticket response should serialize");
    let unknown = serde_json::to_value(TicketResponse::from(ticket_with_status("Deferred")))
        .expect("ticket response should serialize");

    assert_eq!(known["status"], json!("Open"));
    assert_eq!(unknown["status"], json!("Deferred"));
}
