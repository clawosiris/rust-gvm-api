mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::{
    graceful_shutdown_harness, spawn_server, ControlledTargetAdapter, GracefulShutdownHarness,
};
use gvm_gateway::config::NativeTlsFiles;
use gvm_gateway::server;
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::SessionManager;
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::router::build_router;
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use http::StatusCode;
use rcgen::generate_simple_self_signed;
use reqwest::Client;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;

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
async fn e2e_graceful_shutdown_drains_in_flight_requests() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let harness = graceful_shutdown_harness(
        Arc::new(ControlledTargetAdapter::new(
            Arc::clone(&started),
            Arc::clone(&release),
        )),
        Duration::from_secs(1),
    )
    .await;

    let request = spawn_target_request(&harness);

    started.notified().await;
    harness.begin_shutdown();
    tokio::time::sleep(Duration::from_millis(25)).await;
    release.notify_waiters();

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    tokio::time::timeout(Duration::from_secs(1), harness.handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn e2e_graceful_shutdown_forces_exit_after_timeout() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let harness = graceful_shutdown_harness(
        Arc::new(ControlledTargetAdapter::new(
            Arc::clone(&started),
            Arc::clone(&release),
        )),
        Duration::from_millis(50),
    )
    .await;

    let request = spawn_target_request(&harness);

    started.notified().await;
    harness.begin_shutdown();

    tokio::time::timeout(Duration::from_millis(250), harness.handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(
        !request.is_finished(),
        "bounded shutdown should return even if a request is still blocked"
    );

    release.notify_waiters();
    let response = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
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
async fn https_health_returns_200_in_native_tls_mode() {
    let cert_dir = TempDir::new().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, signing_key.serialize_pem()).unwrap();

    let adapter = StaticGvmdAdapter::ready("22.7");
    let service = static_service(adapter.clone(), adapter);
    let app = build_router(service);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(ShutdownRuntime::new());
    let handle = tokio::spawn(server::serve(
        listener,
        app,
        shutdown,
        Duration::from_secs(1),
        Some(NativeTlsFiles {
            certificate_path: cert_path,
            private_key_path: key_path,
        }),
    ));

    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://localhost:{port}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    handle.abort();
}

#[tokio::test]
async fn native_tls_startup_fails_when_pem_pair_is_invalid() {
    let cert_dir = TempDir::new().unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    fs::write(&cert_path, "not a certificate").unwrap();
    fs::write(&key_path, "not a private key").unwrap();

    let adapter = StaticGvmdAdapter::ready("22.7");
    let service = static_service(adapter.clone(), adapter);
    let app = build_router(service);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let shutdown = Arc::new(ShutdownRuntime::new());

    let error = server::serve(
        listener,
        app,
        shutdown,
        Duration::from_secs(1),
        Some(NativeTlsFiles {
            certificate_path: cert_path,
            private_key_path: key_path,
        }),
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("No certificate was found")
            || error.to_string().contains("private key")
            || error.to_string().contains("invalid")
    );
}

fn spawn_target_request(
    harness: &GracefulShutdownHarness,
) -> tokio::task::JoinHandle<Result<reqwest::Response, reqwest::Error>> {
    let client = harness.client.clone();
    let token = harness.token.clone();
    let addr = harness.addr;
    tokio::spawn(async move {
        client
            .get(format!("http://{addr}/api/v1/targets"))
            .bearer_auth(token)
            .send()
            .await
    })
}

fn static_service(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
) -> GatewayService {
    let sessions = Arc::new(SessionManager::default());
    GatewayService::new(
        Arc::new(system_adapter),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        sessions,
    )
}
