// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::*;
use gvm_gateway_domain::{GenericAsset, GenericConfig, SupportingResourceMeta};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn meta() -> SupportingResourceMeta {
    SupportingResourceMeta {
        id: ID.to_string(),
        name: "resource".to_string(),
        comment: None,
        creation_time: None,
        modification_time: None,
        writable: true,
        in_use: false,
    }
}

#[test]
fn generic_queries_preserve_shared_fields_and_open_discriminators() {
    // The generic list endpoints extend the shared filter/pagination parser;
    // known and future discriminator strings must reach the domain unchanged.
    let asset = parse_asset_query(
        "filter=name%3Ddemo&filterId=123e4567-e89b-12d3-a456-426614174000&type=future_asset&page=2&perPage=10",
    )
    .expect("asset query should parse");
    assert_eq!(asset.filter_string.as_deref(), Some("name=demo"));
    assert_eq!(asset.filter_id.as_deref(), Some(ID));
    assert_eq!(asset.asset_type, "future_asset");
    assert_eq!((asset.page, asset.per_page), (2, 10));

    let config =
        parse_config_query("usageType=audit&page=3&perPage=5").expect("config query should parse");
    assert_eq!(config.usage_type.as_deref(), Some("audit"));
    assert_eq!((config.page, config.per_page), (3, 5));
}

#[test]
fn generic_asset_reads_require_a_nonempty_open_type() {
    // Every typed get_assets command requires a type. Enforce that at the REST
    // boundary while still accepting future values rather than emitting an
    // invalid unscoped GMP command.
    assert!(matches!(
        parse_asset_query("page=1"),
        Err(GatewayError::InvalidInput(detail)) if detail.contains("type is required")
    ));
    assert!(matches!(
        required_asset_type("type="),
        Err(GatewayError::InvalidInput(detail)) if detail.contains("must not be empty")
    ));
    assert_eq!(
        required_asset_type("type=future_asset").unwrap(),
        "future_asset"
    );
}

#[test]
fn generic_responses_preserve_known_and_future_discriminator_values() {
    // Open REST discriminators document current values without collapsing a
    // future typed backend value during response serialization.
    let known = GenericAssetResponse::from(GenericAsset {
        meta: meta(),
        asset_type: "tls_certificate".to_string(),
        value: None,
        identifiers: vec![],
        severity: None,
        ip: None,
        hostname: None,
        os: None,
        hosts_count: None,
        title: None,
        installs: None,
        all_installs: None,
        latest_severity: None,
        highest_severity: None,
        average_severity: None,
        host_count: None,
        hosts: vec![],
    });
    let future = GenericConfigResponse::from(GenericConfig {
        id: ID.to_string(),
        name: "future".to_string(),
        comment: None,
        config_type: Some(42),
        usage_type: "future_usage".to_string(),
        in_use: false,
        writable: true,
    });

    assert_eq!(
        serde_json::to_value(known).unwrap()["type"],
        "tls_certificate"
    );
    assert_eq!(
        serde_json::to_value(future).unwrap()["usageType"],
        "future_usage"
    );
}

#[test]
fn generic_asset_mutation_is_comment_only() {
    // Typed gvmd cannot change generic asset values; reject accidental value
    // mutation instead of silently discarding a field while returning success.
    let error = serde_json::from_value::<ModifyGenericAssetRequest>(json!({
        "comment": "updated",
        "value": "192.0.2.10"
    }))
    .expect_err("unsupported value mutation should fail");
    assert!(error.to_string().contains("value"));

    let request = serde_json::from_value::<ModifyGenericAssetRequest>(json!({
        "comment": "updated"
    }))
    .expect("comment-only mutation should parse");
    assert_eq!(
        request.validate_into().unwrap().comment.as_deref(),
        Some("updated")
    );
}

#[test]
fn generic_asset_delete_rejects_unsupported_ultimate_flag() {
    // Generic asset deletion has no typed permanent-delete control, so every
    // spelling of an ultimate query must fail instead of being ignored.
    for query in ["ultimate=true", "ultimate=false", "ult%69mate=true"] {
        assert!(matches!(
            reject_asset_ultimate_query(Some(query)),
            Err(GatewayError::InvalidInput(detail)) if detail.contains("ultimate")
        ));
    }
    reject_asset_ultimate_query(None).expect("missing query should be accepted");
}
