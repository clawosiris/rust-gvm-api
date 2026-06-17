// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::GatewayError;

use super::{
    parse_collection_query, parse_delete_resource_query, parse_filter_only_query,
    CollectionListQuery,
};

#[test]
fn collection_query_decodes_reserved_characters_and_plus_spaces() {
    let parsed = parse_collection_query(
        "filter=severity%3E5+and+name~%22foo%26bar%3Dbaz%22&perPage=10&page=2",
    )
    .expect("query should decode");

    assert_eq!(
        parsed.filter_string.as_deref(),
        Some("severity>5 and name~\"foo&bar=baz\"")
    );
    assert_eq!(parsed.page, 2);
    assert_eq!(parsed.per_page, 10);
}

#[test]
fn collection_query_decodes_uuid_before_validation() {
    let parsed = parse_collection_query("filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000")
        .expect("encoded uuid should validate after decode");

    assert_eq!(
        parsed.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
}

#[test]
fn filter_only_query_decodes_filter_id_before_validation() {
    let parsed = parse_filter_only_query("filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000")
        .expect("encoded uuid should validate");

    assert_eq!(
        parsed.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
}

#[test]
fn collection_query_rejects_oversized_page_size() {
    let error = parse_collection_query("perPage=1001")
        .expect_err("perPage above the documented maximum should fail");

    assert_eq!(
        error,
        GatewayError::InvalidInput("perPage must be between 1 and 1000".to_string())
    );
}

#[test]
fn collection_list_query_wraps_shared_collection_parser() {
    let parsed = CollectionListQuery::try_from_query_string(
        "filter=name%3Dfoo+and+severity%3E5&filterId=123e4567-e89b-12d3-a456-426614174000",
    )
    .expect("shared collection query should parse");

    assert_eq!(
        parsed.filter_string.as_deref(),
        Some("name=foo and severity>5")
    );
    assert_eq!(
        parsed.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(parsed.page, 1);
    assert_eq!(parsed.per_page, 25);
}

#[test]
fn collection_list_query_rejects_invalid_filter_id() {
    let error = CollectionListQuery::try_from_query_string("filterId=not-a-uuid")
        .expect_err("invalid shared filterId should be rejected");

    assert_eq!(
        error,
        GatewayError::InvalidInput("filterId must be a valid UUID".to_string())
    );
}

#[test]
fn delete_resource_query_rejects_invalid_boolean() {
    let error = parse_delete_resource_query("ultimate=not-bool")
        .expect_err("invalid ultimate bool should be rejected");

    match error {
        GatewayError::InvalidInput(detail) => {
            assert_eq!(detail, "ultimate must be true or false");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
