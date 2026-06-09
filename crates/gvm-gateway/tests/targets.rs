mod common;

use common::target_harness;
use gvm_gateway_domain::TargetPage;
use gvm_mock_server::Resource;
use http::StatusCode;
use uuid::Uuid;

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
    let harness = target_harness(|_| {}).await;
    // Regression coverage for the published CreateTarget credential fields:
    // the gateway must accept them and delegate command construction to rust-gvm.
    let ssh_id = "11111111-1111-1111-1111-111111111111";
    let smb_id = "22222222-2222-2222-2222-222222222222";
    let esxi_id = "33333333-3333-3333-3333-333333333333";
    let snmp_id = "44444444-4444-4444-4444-444444444444";

    let response = harness
        .create_target(serde_json::json!({
            "name": "Credential Target",
            "hosts": ["192.168.1.20"],
            "sshCredentialId": ssh_id,
            "smbCredentialId": smb_id,
            "esxiCredentialId": esxi_id,
            "snmpCredentialId": snmp_id
        }))
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let create_record = harness
        .server
        .command_history()
        .into_iter()
        .find(|record| record.command_name() == "create_target")
        .expect("create target command should be sent");
    let request_xml = String::from_utf8(create_record.raw_xml().to_vec()).unwrap();
    assert!(request_xml.contains(&format!(r#"<ssh_credential id="{ssh_id}"/>"#)));
    assert!(request_xml.contains(&format!(r#"<smb_credential id="{smb_id}"/>"#)));
    assert!(request_xml.contains(&format!(r#"<esxi_credential id="{esxi_id}"/>"#)));
    assert!(request_xml.contains(&format!(r#"<snmp_credential id="{snmp_id}"/>"#)));

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
async fn update_target_forwards_credential_ids() {
    let harness = target_harness(|_| {}).await;

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
                "sshCredentialId": "550e8400-e29b-41d4-a716-446655440001",
                "smbCredentialId": "550e8400-e29b-41d4-a716-446655440002",
                "esxiCredentialId": "550e8400-e29b-41d4-a716-446655440003",
                "snmpCredentialId": "550e8400-e29b-41d4-a716-446655440004"
            }),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let history = harness.server.command_history();
    let command = history
        .iter()
        .find(|record| record.command_name() == "modify_target")
        .expect("modify_target command should be recorded");
    let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
    assert!(xml.contains("<ssh_credential id=\"550e8400-e29b-41d4-a716-446655440001\"/>"));
    assert!(xml.contains("<smb_credential id=\"550e8400-e29b-41d4-a716-446655440002\"/>"));
    assert!(xml.contains("<esxi_credential id=\"550e8400-e29b-41d4-a716-446655440003\"/>"));
    assert!(xml.contains("<snmp_credential id=\"550e8400-e29b-41d4-a716-446655440004\"/>"));

    harness.shutdown().await;
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
