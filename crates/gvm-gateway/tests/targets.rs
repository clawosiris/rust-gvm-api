mod common;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use common::{graceful_shutdown_harness, target_harness};
use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, ModifyTargetInput, Pagination, ResourceRef, Target,
    TargetPage, TargetPort, TargetQuery,
};
use gvm_mock_server::{Resource, ResourceStore};
use http::StatusCode;
use uuid::Uuid;

struct CredentialReadbackTargetAdapter;

const SSH_CREDENTIAL_ID: &str = "11111111-1111-1111-1111-111111111111";
const SMB_CREDENTIAL_ID: &str = "22222222-2222-2222-2222-222222222222";
const ESXI_CREDENTIAL_ID: &str = "33333333-3333-3333-3333-333333333333";
const SNMP_CREDENTIAL_ID: &str = "44444444-4444-4444-4444-444444444444";

fn seed_target_credentials(store: &ResourceStore) {
    // Current rust-gvm validates target credential references against backend
    // state, so these tests use existing credentials with compatible types.
    for (id, name, credential_type) in [
        (SSH_CREDENTIAL_ID, "SSH Login", "usk"),
        (SMB_CREDENTIAL_ID, "SMB Login", "up"),
        (ESXI_CREDENTIAL_ID, "ESXi Login", "up"),
        (SNMP_CREDENTIAL_ID, "SNMP Login", "snmp"),
    ] {
        let mut credential = Resource::with_id("credential", name, Uuid::parse_str(id).unwrap());
        credential.set_attr("type", credential_type);
        store.create(credential);
    }
}

fn credential_ref(id: Option<String>, name: &str) -> Option<ResourceRef> {
    id.map(|id| ResourceRef {
        id,
        name: Some(name.to_string()),
    })
}

#[async_trait]
impl TargetPort for CredentialReadbackTargetAdapter {
    async fn list_targets(
        &self,
        _session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        Ok(TargetPage {
            data: Vec::new(),
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_target(
        &self,
        _session_token: &str,
        _input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "create_target is not used by this test adapter".to_string(),
        ))
    }

    async fn clone_target(&self, _session_token: &str, _id: &str) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "clone_target is not used by this test adapter".to_string(),
        ))
    }

    async fn get_target(&self, _session_token: &str, id: &str) -> Result<Target, GatewayError> {
        Ok(Target {
            id: id.to_string(),
            name: "Credential Target".to_string(),
            comment: None,
            hosts: vec!["127.0.0.1".to_string()],
            exclude_hosts: Vec::new(),
            alive_test: None,
            port_list: None,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            ssh_credential: None,
            smb_credential: None,
            esxi_credential: None,
            snmp_credential: None,
            in_use: false,
            writable: true,
        })
    }

    async fn modify_target(
        &self,
        _session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        Ok(Target {
            id: id.to_string(),
            name: input
                .name
                .unwrap_or_else(|| "Credential Target".to_string()),
            comment: input.comment,
            hosts: input.hosts.unwrap_or_else(|| vec!["127.0.0.1".to_string()]),
            exclude_hosts: input.exclude_hosts.unwrap_or_default(),
            alive_test: input.alive_test,
            port_list: input.port_list_id.map(|id| ResourceRef {
                id,
                name: Some("Port List".to_string()),
            }),
            reverse_lookup_only: input.reverse_lookup_only.unwrap_or(false),
            reverse_lookup_unify: input.reverse_lookup_unify.unwrap_or(false),
            ssh_credential: credential_ref(input.ssh_credential_id, "SSH Login"),
            smb_credential: credential_ref(input.smb_credential_id, "SMB Login"),
            esxi_credential: credential_ref(input.esxi_credential_id, "ESXi Login"),
            snmp_credential: credential_ref(input.snmp_credential_id, "SNMP Login"),
            in_use: false,
            writable: true,
        })
    }

    async fn delete_target(
        &self,
        _session_token: &str,
        _id: &str,
        _ultimate: bool,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "delete_target is not used by this test adapter".to_string(),
        ))
    }
}

#[tokio::test]
async fn list_targets_empty() {
    let harness = target_harness(|_| {}).await;

    let response = harness.get_targets().await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["data"], serde_json::json!([]));
    assert_eq!(json["pagination"]["page"], 1);
    assert_eq!(json["pagination"]["perPage"], 25);
    assert_eq!(json["pagination"]["total"], 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn list_targets_paginated() {
    let harness = target_harness(|store| {
        for index in 1..=25 {
            let mut resource = Resource::new("target", &format!("Target-{index}"));
            resource.set_attr("hosts", &format!("10.0.0.{index}"));
            store.create(resource);
        }
    })
    .await;

    let response = harness.get_targets_with_query("page=2&perPage=10").await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<TargetPage>().await.unwrap();
    assert_eq!(json.data.len(), 10);
    assert_eq!(json.pagination.page, 2);
    assert_eq!(json.pagination.per_page, 10);
    assert_eq!(json.pagination.total, 25);
    assert_eq!(json.pagination.total_pages, 3);

    harness.shutdown().await;
}

#[tokio::test]
async fn list_targets_rejects_reserved_filter_pagination_terms() {
    let harness = target_harness(|_| {}).await;

    // Caller filters are composed with gateway-owned pagination terms in
    // rust-gvm, so attempts to supply those terms must fail before gvmd work.
    let response = harness.get_targets_with_query("filter=first%3D1").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 400);
    assert_eq!(json["code"], "bad_request");
    assert!(json["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("reserved term 'first'")));

    harness.shutdown().await;
}

#[tokio::test]
async fn create_target() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .create_target(serde_json::json!({
            "name": "Created Target",
            "hosts": ["192.168.1.10"],
            "comment": "created by acceptance test"
        }))
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let json = response.json::<serde_json::Value>().await.unwrap();
    let id = json["id"].as_str().unwrap();
    assert!(Uuid::parse_str(id).is_ok());
    assert_eq!(location, format!("/api/v1/targets/{id}"));
    assert!(harness
        .server
        .command_history()
        .iter()
        .any(|record| record.command_name() == "create_target"));

    harness.shutdown().await;
}

#[tokio::test]
async fn create_target_accepts_documented_credential_ids() {
    let harness = target_harness(seed_target_credentials).await;
    // Regression coverage for the published CreateTarget credential fields:
    // the gateway must accept valid references and delegate command construction.

    let response = harness
        .create_target(serde_json::json!({
            "name": "Credential Target",
            "hosts": ["192.168.1.20"],
            "sshCredentialId": SSH_CREDENTIAL_ID,
            "smbCredentialId": SMB_CREDENTIAL_ID,
            "esxiCredentialId": ESXI_CREDENTIAL_ID,
            "snmpCredentialId": SNMP_CREDENTIAL_ID
        }))
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(harness
        .server
        .command_history()
        .iter()
        .any(|record| record.command_name() == "create_target"));

    harness.shutdown().await;
}

#[tokio::test]
async fn create_target_missing_name() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .create_target(serde_json::json!({
            "hosts": ["192.168.1.10"]
        }))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 400);

    harness.shutdown().await;
}

#[tokio::test]
async fn get_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .create_target(serde_json::json!({
            "name": "Existing Target",
            "hosts": ["127.0.0.1"]
        }))
        .await;
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness.get_target(&id).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["name"], "Existing Target");
    assert_eq!(json["hosts"], serde_json::json!(["127.0.0.1"]));

    harness.shutdown().await;
}

#[tokio::test]
async fn get_target_not_found() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .get_target("550e8400-e29b-41d4-a716-446655440000")
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    harness.shutdown().await;
}

#[tokio::test]
async fn update_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .create_target(serde_json::json!({
            "name": "Before Update",
            "hosts": ["127.0.0.1"]
        }))
        .await;
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .update_target(
            &id,
            serde_json::json!({
                "name": "After Update",
                "hosts": ["10.0.0.8", "10.0.0.9"]
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["name"], "After Update");
    assert_eq!(json["hosts"], serde_json::json!(["10.0.0.8", "10.0.0.9"]));

    harness.shutdown().await;
}

#[tokio::test]
async fn update_target_accepts_credential_ids() {
    let harness = target_harness(seed_target_credentials).await;

    let create_response = harness
        .create_target(serde_json::json!({
            "name": "Credential Target",
            "hosts": ["127.0.0.1"]
        }))
        .await;
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    harness.server.clear_history();

    let response = harness
        .update_target(
            &id,
            serde_json::json!({
                "sshCredentialId": SSH_CREDENTIAL_ID,
                "smbCredentialId": SMB_CREDENTIAL_ID,
                "esxiCredentialId": ESXI_CREDENTIAL_ID,
                "snmpCredentialId": SNMP_CREDENTIAL_ID
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(harness
        .server
        .command_history()
        .iter()
        .any(|record| record.command_name() == "modify_target"));

    harness.shutdown().await;
}

#[tokio::test]
async fn update_target_response_includes_credential_refs() {
    // Regression coverage for issue #228: modify-target responses must reflect
    // credential bindings instead of returning a stale Target body with them absent.
    let harness = graceful_shutdown_harness(
        Arc::new(CredentialReadbackTargetAdapter),
        Duration::from_secs(1),
    )
    .await;
    let target_id = "550e8400-e29b-41d4-a716-446655440000";

    let response = harness
        .client
        .put(format!(
            "http://{}/api/v1/targets/{target_id}",
            harness.addr
        ))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "sshCredentialId": "550e8400-e29b-41d4-a716-446655440001",
            "smbCredentialId": "550e8400-e29b-41d4-a716-446655440002",
            "esxiCredentialId": "550e8400-e29b-41d4-a716-446655440003",
            "snmpCredentialId": "550e8400-e29b-41d4-a716-446655440004"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["sshCredential"],
        serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "name": "SSH Login"
        })
    );
    assert_eq!(
        json["smbCredential"],
        serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440002",
            "name": "SMB Login"
        })
    );
    assert_eq!(
        json["esxiCredential"],
        serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440003",
            "name": "ESXi Login"
        })
    );
    assert_eq!(
        json["snmpCredential"],
        serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440004",
            "name": "SNMP Login"
        })
    );

    harness.handle.abort();
}

#[tokio::test]
async fn update_target_accepts_reverse_lookup_flags() {
    // Regression coverage for issue #309: reverse lookup flags are mutable
    // target settings, so PUT must deserialize and pass them through.
    let harness = graceful_shutdown_harness(
        Arc::new(CredentialReadbackTargetAdapter),
        Duration::from_secs(1),
    )
    .await;
    let target_id = "550e8400-e29b-41d4-a716-446655440000";

    let response = harness
        .client
        .put(format!(
            "http://{}/api/v1/targets/{target_id}",
            harness.addr
        ))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "reverseLookupOnly": true,
            "reverseLookupUnify": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["reverseLookupOnly"], true);
    assert_eq!(json["reverseLookupUnify"], false);

    harness.handle.abort();
}

#[tokio::test]
async fn delete_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .create_target(serde_json::json!({
            "name": "Delete Me",
            "hosts": ["127.0.0.1"]
        }))
        .await;
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness.delete_target(&id).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    harness.shutdown().await;
}

#[tokio::test]
async fn delete_target_not_found() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .delete_target("550e8400-e29b-41d4-a716-446655440000")
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    harness.shutdown().await;
}

#[tokio::test]
async fn method_not_allowed() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .patch(harness.url("/api/v1/targets"))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    harness.shutdown().await;
}
