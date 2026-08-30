// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::GatewayError;

use super::credentials::{
    credential_store_capability_unavailable, unsupported_credential_store_error,
};

#[test]
fn credential_store_capability_unavailable_accepts_command_disabled_response() {
    // Regression coverage for disabled gvmd credential-store capability when
    // the typed client raises the raw server-status error before parsing.
    let error = gvm_client::GvmError::Server {
        status: 503,
        message: "Service unavailable: Command disabled".to_string(),
    };

    assert!(credential_store_capability_unavailable(&error));
}

#[test]
fn credential_store_capability_unavailable_accepts_typed_parse_status_response() {
    // Regression coverage for PR #463 live E2E on 2026-08-29: typed
    // get_credential_stores parsing can surface disabled gvmd commands as a
    // ParseError::ServerError, and that capability absence still maps to 501.
    let error = gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
        status: 503,
        message: "Service unavailable: Command disabled".to_string(),
    });

    assert!(credential_store_capability_unavailable(&error));
}

#[test]
fn credential_store_capability_unavailable_rejects_unrelated_server_errors() {
    // Only the credential-store-specific capability response should map to
    // 501. Other backend 503s must continue to surface as generic bad gateway
    // failures through the shared error mapping.
    let error = gvm_client::GvmError::Server {
        status: 503,
        message: "Service unavailable: database offline".to_string(),
    };

    assert!(!credential_store_capability_unavailable(&error));
}

#[test]
fn credential_store_capability_unavailable_rejects_unrelated_parse_status_errors() {
    // A typed 503 parser status without the disabled-command reason remains a
    // backend outage and must not be converted to NotImplemented.
    let error = gvm_client::GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
        status: 503,
        message: "Service unavailable: database offline".to_string(),
    });

    assert!(!credential_store_capability_unavailable(&error));
}

#[test]
fn unsupported_credential_store_error_documents_no_synthesis_boundary() {
    // The gateway advertises capability absence instead of inventing a default
    // credential store when gvmd does not expose this command.
    let GatewayError::NotImplemented(detail) = unsupported_credential_store_error() else {
        panic!("credential-store capability absence should map to not implemented");
    };

    assert!(detail.contains("get_credential_stores"));
    assert!(detail.contains("does not synthesize credential store entries"));
}
