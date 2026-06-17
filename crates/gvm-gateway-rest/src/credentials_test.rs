// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{
    credential_json_body_error, CreateCredentialRequest, CredentialResponse, CredentialType,
    ModifyCredentialRequest,
};
use gvm_gateway_domain::{Credential, GatewayError};

fn credential_with_type(credential_type: &str) -> Credential {
    Credential {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Credential".to_string(),
        comment: None,
        credential_type: Some(credential_type.to_string()),
        login: Some("user".to_string()),
        in_use: false,
        writable: true,
    }
}

#[test]
fn credential_type_deserialization_preserves_unknown_values() {
    // Backend-added credential types must survive deserialization instead
    // of being rejected by the open-enum wrapper.
    let parsed: CredentialType =
        serde_json::from_value(json!("future_credential")).expect("type should parse");

    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        json!("future_credential")
    );
}

#[test]
fn credential_response_preserves_known_and_unknown_types() {
    // Response conversion should expose both known rust-gvm type values and
    // future backend values without collapsing the public `type` field.
    let known = serde_json::to_value(CredentialResponse::from(credential_with_type("up")))
        .expect("credential response should serialize");
    let unknown = serde_json::to_value(CredentialResponse::from(credential_with_type(
        "future_credential",
    )))
    .expect("credential response should serialize");

    assert_eq!(known["type"], json!("up"));
    assert_eq!(unknown["type"], json!("future_credential"));
}

#[test]
fn credential_request_debug_redacts_secrets() {
    // Request DTOs carry write-only credential secrets; debug output must
    // only expose their presence, never their submitted values.
    let create = CreateCredentialRequest {
        name: "Credential".to_string(),
        comment: Some("visible comment".to_string()),
        credential_type: "snmpv3".to_string(),
        login: Some("visible-login".to_string()),
        password: Some("create-password-secret".to_string()),
        private_key: Some("create-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("create-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("create-privacy-secret".to_string()),
    };
    let modify = ModifyCredentialRequest {
        name: Some("Credential".to_string()),
        comment: Some("visible comment".to_string()),
        login: Some("visible-login".to_string()),
        password: Some("modify-password-secret".to_string()),
        private_key: Some("modify-private-key-secret".to_string()),
        certificate: Some("public-certificate".to_string()),
        community: Some("modify-community-secret".to_string()),
        auth_algorithm: Some("sha1".to_string()),
        privacy_algorithm: Some("aes".to_string()),
        privacy_password: Some("modify-privacy-secret".to_string()),
    };

    let debug = format!("{create:?}\n{modify:?}");

    assert!(debug.contains("visible-login"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("create-password-secret"));
    assert!(!debug.contains("create-private-key-secret"));
    assert!(!debug.contains("create-community-secret"));
    assert!(!debug.contains("create-privacy-secret"));
    assert!(!debug.contains("modify-password-secret"));
    assert!(!debug.contains("modify-private-key-secret"));
    assert!(!debug.contains("modify-community-secret"));
    assert!(!debug.contains("modify-privacy-secret"));
}

#[test]
fn credential_json_parse_error_detail_omits_submitted_values() {
    // Credential parse failures become client-visible problem details, so
    // the detail string must not reuse serde's value-bearing error text.
    let error = serde_json::from_value::<CreateCredentialRequest>(json!({
        "name": "Credential",
        "type": "up",
        "password": 123456789,
        "privateKey": 987654321,
        "community": 111222333,
        "privacyPassword": 444555666
    }))
    .expect_err("numeric secret fields should fail string deserialization");

    let GatewayError::InvalidInput(detail) = credential_json_body_error(error) else {
        panic!("credential parse errors should map to invalid input");
    };

    assert!(detail.starts_with("invalid JSON body at line "));
    assert!(!detail.contains("123456789"));
    assert!(!detail.contains("987654321"));
    assert!(!detail.contains("111222333"));
    assert!(!detail.contains("444555666"));
}
