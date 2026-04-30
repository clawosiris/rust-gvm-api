//! Acceptance tests for the GVM gateway service.
//!
//! These tests validate the complete service behavior including health,
//! readiness, version endpoints, and full target CRUD operations via
//! the REST adapter backed by a mock GMP server.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{target_from_gmp, TargetPage};
use gvm_gateway_gvmd::{GvmdAdapter, StaticGvmdAdapter};
use gvm_gateway_rest::router::build_router;
use gvm_gateway_rest::targets::{
    build_gmp_filter, CreateTargetRequest, ModifyTargetRequest, TargetListQuery,
};
use gvm_gmp::responses::GetTargetsResponse;
use gvm_mock_server::{
    GmpVersion as MockVersion, MockGmpServer, Resource, ResourceStore, ServerMode,
};
use gvm_protocol::Response as GmpResponse;
use http::StatusCode;
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

async fn spawn_server(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = GatewayService::new(Arc::new(system_adapter), Arc::new(target_adapter));
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ============================================================================
// Health & Readiness Tests
// ============================================================================

#[tokio::test]
async fn health_returns_200() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({ "status": "ok" })
    );

    handle.abort();
}

#[tokio::test]
async fn ready_returns_200_when_ready() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({ "status": "ready" })
    );

    handle.abort();
}

#[tokio::test]
async fn ready_returns_503_when_not_ready() {
    let adapter = StaticGvmdAdapter::not_ready("gvmd unavailable", "22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({ "status": "notReady", "reason": "gvmd unavailable" })
    );

    handle.abort();
}

#[tokio::test]
async fn version_returns_api_and_gmp_version() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/version"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["apiVersion"], serde_json::json!("0.3.1"));
    assert_eq!(json["gmpVersion"], serde_json::json!("22.7"));

    handle.abort();
}

#[tokio::test]
async fn generated_openapi_endpoint_exposes_implemented_contract() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/json"
    );

    let json = response.json::<Value>().await.unwrap();
    let root_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/openapi.yaml")).unwrap();
    let system_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/system.yaml")).unwrap();
    let targets_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();

    assert_eq!(json["servers"], root_spec["servers"]);
    assert_eq!(json["security"], root_spec["security"]);
    assert_eq!(
        path_names(&json),
        BTreeSet::from([
            "/health",
            "/openapi.json",
            "/ready",
            "/targets",
            "/targets/{id}",
            "/version",
        ])
    );

    let checks = [
        ("/health", "get", &system_spec, "/health", &["200"] as &[_]),
        ("/ready", "get", &system_spec, "/ready", &["200", "503"]),
        ("/version", "get", &system_spec, "/version", &["200", "502"]),
        (
            "/openapi.json",
            "get",
            &system_spec,
            "/openapi.json",
            &["200"],
        ),
        (
            "/targets",
            "get",
            &targets_spec,
            "/targets",
            &["200", "401"],
        ),
        (
            "/targets",
            "post",
            &targets_spec,
            "/targets",
            &["201", "400", "401"],
        ),
        (
            "/targets/{id}",
            "get",
            &targets_spec,
            "/targets/{id}",
            &["200", "401", "404"],
        ),
        (
            "/targets/{id}",
            "put",
            &targets_spec,
            "/targets/{id}",
            &["200", "400", "401", "404"],
        ),
        (
            "/targets/{id}",
            "delete",
            &targets_spec,
            "/targets/{id}",
            &["204", "401", "404"],
        ),
    ];

    for (generated_path, method, curated_doc, curated_path, statuses) in checks {
        let generated_op = op(&json, generated_path, method);
        let curated_op = op(curated_doc, curated_path, method);

        assert_eq!(generated_op["operationId"], curated_op["operationId"]);
        assert_eq!(generated_op["tags"], curated_op["tags"]);
        assert_eq!(generated_op["summary"], curated_op["summary"]);

        let generated_statuses = response_statuses(generated_op);
        for status in statuses {
            assert!(
                generated_statuses.contains(status),
                "missing generated status {status} for {method} {generated_path}"
            );
        }
    }

    let target_props = &json["components"]["schemas"]["Target"]["properties"];
    assert!(target_props.get("excludeHosts").is_some());
    assert!(target_props.get("aliveTest").is_some());
    assert!(target_props.get("portList").is_some());
    assert_eq!(target_props["id"]["format"], "uuid");

    let pagination_props = &json["components"]["schemas"]["Pagination"]["properties"];
    assert!(pagination_props.get("perPage").is_some());
    assert!(pagination_props.get("totalPages").is_some());

    handle.abort();
}

fn op<'a>(doc: &'a Value, path: &str, method: &str) -> &'a Value {
    &doc["paths"][path][method]
}

fn path_names(doc: &Value) -> BTreeSet<&str> {
    doc["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn response_statuses(operation: &Value) -> BTreeSet<&str> {
    operation["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

// ============================================================================
// Trace Context & Error Handling Tests
// ============================================================================

#[tokio::test]
async fn trace_context_headers_propagated() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/health"))
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        )
        .header("tracestate", "vendor=value")
        .header("baggage", "user_id=123")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("traceparent").unwrap(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
    );
    assert_eq!(
        response.headers().get("tracestate").unwrap(),
        "vendor=value"
    );
    assert_eq!(response.headers().get("baggage").unwrap(), "user_id=123");

    handle.abort();
}

#[tokio::test]
async fn problem_details_shape_on_error() {
    let adapter = StaticGvmdAdapter::not_ready("backend offline", "22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/version"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("urn:gvm-gateway:problem:bad-gateway")
    );
    assert_eq!(json["title"], serde_json::json!("Bad Gateway"));
    assert_eq!(json["status"], serde_json::json!(502));
    assert_eq!(json["detail"], serde_json::json!("backend offline"));
    assert_eq!(json["instance"], serde_json::json!("/api/v1/version"));

    handle.abort();
}

#[tokio::test]
async fn not_found_route_returns_404_problem() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("urn:gvm-gateway:problem:not-found")
    );
    assert_eq!(json["title"], serde_json::json!("Not Found"));
    assert_eq!(json["status"], serde_json::json!(404));
    assert_eq!(json["instance"], serde_json::json!("/does-not-exist"));

    handle.abort();
}

// ============================================================================
// Domain Type Unit Tests (moved from adapter)
// ============================================================================

#[test]
fn target_from_gmp_roundtrip() {
    let response = GmpResponse::from(
        r#"<get_targets_response status="200" status_text="OK">
            <target id="550e8400-e29b-41d4-a716-446655440000">
                <owner><name>admin</name></owner>
                <name>Example Target</name>
                <comment>demo</comment>
                <creation_time>2026-03-27T00:00:00Z</creation_time>
                <modification_time>2026-03-27T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>0</in_use>
                <hosts>10.0.0.1,10.0.0.2</hosts>
                <exclude_hosts>10.0.0.3</exclude_hosts>
                <alive_tests>ICMP Ping</alive_tests>
                <reverse_lookup_only>1</reverse_lookup_only>
                <reverse_lookup_unify>0</reverse_lookup_unify>
                <port_list id="11111111-1111-1111-1111-111111111111"><name>All TCP</name></port_list>
            </target>
        </get_targets_response>"#,
    );
    let parsed = GetTargetsResponse::from_response(&response).unwrap();

    let target = target_from_gmp(parsed.items.into_iter().next().unwrap());

    assert_eq!(target.id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(target.name, "Example Target");
    assert_eq!(target.comment.as_deref(), Some("demo"));
    assert_eq!(target.hosts, vec!["10.0.0.1", "10.0.0.2"]);
    assert_eq!(target.exclude_hosts, vec!["10.0.0.3"]);
    assert_eq!(target.alive_test.as_deref(), Some("ICMP Ping"));
    assert!(target.reverse_lookup_only);
    assert!(!target.reverse_lookup_unify);
    assert_eq!(target.port_list.unwrap().name.as_deref(), Some("All TCP"));
}

#[test]
fn pagination_defaults() {
    let query = TargetListQuery::try_from_query_string("").unwrap();

    assert_eq!(query.page, 1);
    assert_eq!(query.per_page, 25);
}

#[test]
fn pagination_bounds() {
    let query = TargetListQuery::try_from_query_string("perPage=5000").unwrap();

    assert_eq!(query.per_page, 1000);
}

#[test]
fn filter_to_gmp_string() {
    let filter = build_gmp_filter(Some("name=Target-7".to_string()), None);

    assert_eq!(filter.as_deref(), Some("name=Target-7"));
}

#[test]
fn uuid_validation() {
    assert!(TargetListQuery::try_from_query_string("filterId=not-a-uuid").is_err());
    assert!(CreateTargetRequest {
        name: Some("target".to_string()),
        comment: None,
        hosts: vec!["127.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: Some("not-a-uuid".to_string()),
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
    assert!(ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: Some("still-not-a-uuid".to_string()),
    }
    .validate()
    .is_err());
}

// ============================================================================
// Target CRUD Acceptance Tests (with mock GMP server)
// ============================================================================

#[tokio::test]
async fn list_targets_empty() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

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

    let response = harness
        .client
        .get(format!(
            "http://{}/api/v1/targets?page=2&perPage=10",
            harness.addr
        ))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

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
        .client
        .post(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "name": "Created Target",
            "hosts": ["192.168.1.10"],
            "comment": "created by acceptance test"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = response.json::<serde_json::Value>().await.unwrap();
    let id = json["id"].as_str().unwrap();
    assert!(Uuid::parse_str(id).is_ok());
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
        .client
        .post(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "hosts": ["192.168.1.10"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 400);

    harness.shutdown().await;
}

#[tokio::test]
async fn get_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .client
        .post(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "name": "Existing Target",
            "hosts": ["127.0.0.1"]
        }))
        .send()
        .await
        .unwrap();
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets/{id}", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

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
        .client
        .get(format!(
            "http://{}/api/v1/targets/550e8400-e29b-41d4-a716-446655440000",
            harness.addr
        ))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    harness.shutdown().await;
}

#[tokio::test]
async fn update_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .client
        .post(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "name": "Before Update",
            "hosts": ["127.0.0.1"]
        }))
        .send()
        .await
        .unwrap();
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .client
        .put(format!("http://{}/api/v1/targets/{id}", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "name": "After Update",
            "hosts": ["10.0.0.8", "10.0.0.9"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["name"], "After Update");
    assert_eq!(json["hosts"], serde_json::json!(["10.0.0.8", "10.0.0.9"]));

    harness.shutdown().await;
}

#[tokio::test]
async fn delete_target() {
    let harness = target_harness(|_| {}).await;

    let create_response = harness
        .client
        .post(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .json(&serde_json::json!({
            "name": "Delete Me",
            "hosts": ["127.0.0.1"]
        }))
        .send()
        .await
        .unwrap();
    let id = create_response.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .client
        .delete(format!("http://{}/api/v1/targets/{id}", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    harness.shutdown().await;
}

#[tokio::test]
async fn delete_target_not_found() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .delete(format!(
            "http://{}/api/v1/targets/550e8400-e29b-41d4-a716-446655440000",
            harness.addr
        ))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    harness.shutdown().await;
}

#[tokio::test]
async fn method_not_allowed() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .patch(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    harness.shutdown().await;
}

// ============================================================================
// Test Harness
// ============================================================================

struct TargetHarness {
    addr: SocketAddr,
    client: Client,
    token: String,
    server: MockGmpServer,
    handle: tokio::task::JoinHandle<()>,
}

impl TargetHarness {
    async fn shutdown(self) {
        self.handle.abort();
        self.server.shutdown().await;
    }
}

async fn target_harness(seed: impl FnOnce(&ResourceStore) + Send + 'static) -> TargetHarness {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .seed(seed)
        .build()
        .await
        .unwrap();

    let target_adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let service = GatewayService::new(
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(target_adapter.clone()),
    );
    let token = service.session_manager().create("admin").unwrap().token;
    target_adapter
        .connect_session(&token, "admin", "admin")
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TargetHarness {
        addr,
        client: Client::new(),
        token,
        server,
        handle,
    }
}
