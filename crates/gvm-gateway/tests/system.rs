mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::{
    graceful_shutdown_harness, spawn_server, specialized_target_harness, target_harness,
    ControlledTargetAdapter, GracefulShutdownHarness,
};
use gvm_gateway::config::NativeTlsFiles;
use gvm_gateway::server;
use gvm_gateway_app::{GatewayPorts, GatewayService};
use gvm_gateway_domain::SessionManager;
use gvm_gateway_gvmd::{GvmdAdapter, StaticGvmdAdapter};
use gvm_gateway_rest::router::{
    build_router, build_router_with_runtime_and_security, RestSecurityConfig,
};
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use gvm_mock_server::{Fault, FaultKind, GmpVersion as MockVersion, MockGmpServer, ServerMode};
use http::StatusCode;
use rcgen::generate_simple_self_signed;
use reqwest::Client;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
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
    assert_eq!(
        json["apiVersion"],
        serde_json::json!(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(json["gmpVersion"], serde_json::json!("22.7"));

    handle.abort();
}

#[tokio::test]
async fn timezones_return_backend_catalog_when_supported() {
    // Regression coverage for PR #312's reversal condition: the route is only
    // valid if it reflects gvmd's live catalog rather than proxy-local files.
    let harness = specialized_target_harness(|_| {}).await;
    let session = harness.create_session_with_basic("admin", "admin").await;
    assert_eq!(session.status(), StatusCode::CREATED);
    let token = session.json::<serde_json::Value>().await.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .client
        .get(harness.url("/api/v1/timezones"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "data": [
                { "name": "UTC" },
                { "name": "Europe/Berlin", "offset": "+01:00" }
            ]
        })
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn timezones_return_501_when_backend_lacks_get_timezones() {
    // This preserves the August 3, 2026 / August 5, 2026 review constraint
    // from PR #425: older backends must fail explicitly as unsupported rather
    // than looking like generic backend outages.
    let harness = target_harness(|_| {}).await;
    let session = harness.create_session_with_basic("admin", "admin").await;
    assert_eq!(session.status(), StatusCode::CREATED);
    let token = session.json::<serde_json::Value>().await.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .client
        .get(harness.url("/api/v1/timezones"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let problem = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(problem["code"], serde_json::json!("not_implemented"));
    assert_eq!(problem["status"], serde_json::json!(501));
    assert_eq!(problem["instance"], serde_json::json!("/api/v1/timezones"));

    harness.shutdown().await;
}

#[tokio::test]
async fn https_health_returns_200_and_hsts_in_native_tls_mode() {
    let cert_dir = TempDir::new().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, signing_key.serialize_pem()).unwrap();

    let adapter = StaticGvmdAdapter::ready("22.7");
    let service = static_service(adapter.clone(), adapter);
    let shutdown = Arc::new(ShutdownRuntime::new());
    let security = RestSecurityConfig {
        native_tls_enabled: true,
        ..Default::default()
    };
    // Native TLS is the only mode where this process may assert HSTS directly.
    let app = build_router_with_runtime_and_security(service, Arc::clone(&shutdown), security);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
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
    assert_eq!(
        response.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    handle.abort();
}

#[tokio::test]
async fn native_tls_slow_handshake_does_not_block_later_connections() {
    let cert_dir = TempDir::new().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, signing_key.serialize_pem()).unwrap();

    let adapter = StaticGvmdAdapter::ready("22.7");
    let service = static_service(adapter.clone(), adapter);
    let shutdown = Arc::new(ShutdownRuntime::new());
    let security = RestSecurityConfig {
        native_tls_enabled: true,
        ..Default::default()
    };
    let app = build_router_with_runtime_and_security(service, Arc::clone(&shutdown), security);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
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

    // Regression test for the native TLS accept loop: an idle TCP client that
    // never sends handshake bytes must not block subsequent connections.
    let _stalled_handshake = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let request = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://localhost:{port}/health"))
        .send();
    let response = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .expect("later native TLS connection should not wait behind a stalled handshake")
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

#[tokio::test]
async fn credential_store_capability_absence_keeps_following_credentials_route_usable() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .inject_fault(Fault::on_command(
            "get_credential_stores",
            FaultKind::ErrorStatus {
                code: 503,
                message: "Service unavailable: Command disabled".to_string(),
            },
        ))
        .inject_fault(Fault::after_commands(3, FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .unwrap();

    let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let service = live_service(adapter.clone());
    let token = service.session_manager().create("admin").unwrap().token;
    adapter
        .connect_session(&token, "admin", "admin")
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Regression coverage for GitHub run 33263885269 on 2026-08-29: a
    // documented 501 credential-store capability probe must not poison the
    // authenticated GMP session for the immediately following credentials list.
    let client = Client::new();
    let store_response = client
        .get(format!("http://{addr}/api/v1/credential-stores"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(store_response.status(), StatusCode::NOT_IMPLEMENTED);
    let store_problem = store_response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(store_problem["code"], serde_json::json!("not_implemented"));

    let credential_response = client
        .get(format!("http://{addr}/api/v1/credentials?perPage=1000"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(credential_response.status(), StatusCode::OK);
    let credential_page = credential_response
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(credential_page.get("data").is_some());
    assert!(credential_page.get("pagination").is_some());

    handle.abort();
    server.shutdown().await;
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
        GatewayPorts {
            system: Arc::new(system_adapter),
            alerts: Arc::new(target_adapter.clone()),
            schedules: Arc::new(target_adapter.clone()),
            credentials: Arc::new(target_adapter.clone()),
            port_lists: Arc::new(target_adapter.clone()),
            feeds: Arc::new(target_adapter.clone()),
            identity: Arc::new(target_adapter.clone()),
            targets: Arc::new(target_adapter),
            tasks: Arc::new(StaticGvmdAdapter::ready("22.7")),
            auth: Arc::new(StaticGvmdAdapter::ready("22.7")),
            reports: Arc::new(StaticGvmdAdapter::ready("22.7")),
            results: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scan_configs: Arc::new(StaticGvmdAdapter::ready("22.7")),
            scanners: Arc::new(StaticGvmdAdapter::ready("22.7")),
            agents: Arc::new(StaticGvmdAdapter::ready("22.7")),
            supporting_resources: Arc::new(StaticGvmdAdapter::ready("22.7")),
        },
        sessions,
    )
}

fn live_service(adapter: GvmdAdapter) -> GatewayService {
    let sessions = Arc::new(SessionManager::default());
    GatewayService::new(
        GatewayPorts {
            system: Arc::new(StaticGvmdAdapter::ready("22.7")),
            alerts: Arc::new(adapter.clone()),
            schedules: Arc::new(adapter.clone()),
            credentials: Arc::new(adapter.clone()),
            port_lists: Arc::new(adapter.clone()),
            feeds: Arc::new(adapter.clone()),
            identity: Arc::new(adapter.clone()),
            targets: Arc::new(adapter.clone()),
            tasks: Arc::new(adapter.clone()),
            auth: Arc::new(adapter.clone()),
            reports: Arc::new(adapter.clone()),
            results: Arc::new(adapter.clone()),
            scan_configs: Arc::new(adapter.clone()),
            scanners: Arc::new(adapter.clone()),
            agents: Arc::new(adapter.clone()),
            supporting_resources: Arc::new(adapter),
        },
        sessions,
    )
}
