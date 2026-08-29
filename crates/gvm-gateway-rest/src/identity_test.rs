// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    AuthenticationType, IdentityListQuery, ModifyUserRequest, UserResponse, UserSettingsListQuery,
};
use gvm_gateway_domain::{IdentityResourceMeta, User};

#[test]
fn identity_queries_decode_filters_and_filter_ids() {
    let identity = IdentityListQuery::try_from_query_string(
            "filter=name~%22ops+team%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&page=3&perPage=5",
        )
        .expect("identity query should parse");
    assert_eq!(identity.filter_string.as_deref(), Some("name~\"ops team\""));
    assert_eq!(
        identity.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(identity.page, 3);
    assert_eq!(identity.per_page, 5);

    let user_settings = UserSettingsListQuery::try_from_query_string(
        "filter=name~%22foo%20bar%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000",
    )
    .expect("user settings query should parse");
    assert_eq!(
        user_settings.filter_string.as_deref(),
        Some("name~\"foo bar\"")
    );
    assert_eq!(
        user_settings.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
}

fn user_with_auth_type(authentication_type: &str) -> User {
    User {
        meta: IdentityResourceMeta {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            name: "user".to_string(),
            comment: None,
            owner: None,
            creation_time: None,
            modification_time: None,
            writable: true,
            in_use: false,
        },
        roles: vec![],
        groups: vec![],
        hosts_allow: None,
        hosts: None,
        authentication_type: Some(authentication_type.to_string()),
    }
}

#[test]
fn authentication_type_deserialization_preserves_unknown_values() {
    // User authentication backends can grow in gvmd. The response wrapper
    // must preserve that value even before request validation supports it.
    let parsed: AuthenticationType =
        serde_json::from_value(json!("oidc_connect")).expect("auth type should parse");

    assert_eq!(serde_json::to_value(parsed).unwrap(), json!("oidc_connect"));
}

#[test]
fn user_response_preserves_known_and_unknown_authentication_types() {
    // User response conversion should expose the exact backend
    // authenticationType value without coercing unknown future backends.
    let known = serde_json::to_value(UserResponse::from(user_with_auth_type("file")))
        .expect("user response should serialize");
    let unknown = serde_json::to_value(UserResponse::from(user_with_auth_type("oidc_connect")))
        .expect("user response should serialize");

    assert_eq!(known["authenticationType"], json!("file"));
    assert_eq!(unknown["authenticationType"], json!("oidc_connect"));
}

#[test]
fn modify_user_request_preserves_rename_and_explicit_role_clear() {
    // Regression coverage for #404 and #405: a user rename must be forwarded,
    // while [] remains distinguishable from an omitted roles property.
    let clear: ModifyUserRequest = serde_json::from_value(json!({
        "name": "renamed-user",
        "roles": []
    }))
    .expect("rename and empty roles should deserialize");
    let omitted: ModifyUserRequest =
        serde_json::from_value(json!({})).expect("omitted roles should deserialize");

    let clear = clear.validate().expect("empty roles are a valid clear");
    let omitted = omitted.validate().expect("omitted roles are valid");

    assert_eq!(clear.name.as_deref(), Some("renamed-user"));
    assert_eq!(clear.role_ids, Some(Vec::new()));
    assert_eq!(omitted.role_ids, None);
}
