//! Acceptance tests for the GVM gateway service.
//!
//! These tests validate the complete service behavior including health,
//! readiness, version endpoints, and full target CRUD operations via
//! the REST adapter backed by a mock GMP server.

use async_trait::async_trait;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gvm_gateway::server;
use gvm_gateway_app::{GatewayService, SessionReaper};
use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, ModifyTargetInput, Pagination, SessionManager, Target,
    TargetPage, TargetPort, TargetQuery,
};
use gvm_gateway_gvmd::{GvmdAdapter, StaticGvmdAdapter};
use gvm_gateway_rest::router::{
    build_router, build_router_with_runtime_and_security, build_router_with_security,
    RateLimitConfig, RestSecurityConfig,
};
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use gvm_gateway_rest::targets::{
    build_gmp_filter, CreateTargetRequest, ModifyTargetRequest, TargetListQuery,
};
use gvm_mock_server::{
    GmpVersion as MockVersion, MockGmpServer, Resource, ResourceStore, ServerMode,
};
use http::StatusCode;
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;

async fn spawn_server(
    system_adapter: StaticGvmdAdapter,
    target_adapter: StaticGvmdAdapter,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task_adapter = StaticGvmdAdapter::ready("22.7");
    let auth_adapter = StaticGvmdAdapter::ready("22.7");
    let report_adapter = StaticGvmdAdapter::ready("22.7");
    let result_adapter = StaticGvmdAdapter::ready("22.7");
    let scan_config_adapter = StaticGvmdAdapter::ready("22.7");
    let scanner_adapter = StaticGvmdAdapter::ready("22.7");
    let sessions = Arc::new(SessionManager::default());
    let service = GatewayService::new(
        Arc::new(system_adapter),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(target_adapter),
        Arc::new(task_adapter),
        Arc::new(auth_adapter),
        Arc::new(report_adapter),
        Arc::new(result_adapter),
        Arc::new(scan_config_adapter),
        Arc::new(scanner_adapter),
        sessions,
    );
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

struct GracefulShutdownHarness {
    addr: SocketAddr,
    client: Client,
    token: String,
    shutdown: Arc<ShutdownRuntime>,
    handle: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl GracefulShutdownHarness {
    fn begin_shutdown(&self) {
        self.shutdown.begin_shutdown();
    }
}

struct ControlledTargetAdapter {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl ControlledTargetAdapter {
    fn new(started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self { started, release }
    }
}

#[async_trait]
impl TargetPort for ControlledTargetAdapter {
    async fn list_targets(
        &self,
        _session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(TargetPage {
            data: Vec::<Target>::new(),
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
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn get_target(&self, _session_token: &str, _id: &str) -> Result<Target, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn modify_target(
        &self,
        _session_token: &str,
        _id: &str,
        _input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }

    async fn delete_target(&self, _session_token: &str, _id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "not implemented in test adapter".to_string(),
        ))
    }
}

async fn graceful_shutdown_harness(
    target_adapter: Arc<dyn TargetPort>,
    drain_timeout: Duration,
) -> GracefulShutdownHarness {
    let sessions = Arc::new(SessionManager::default());
    let token = sessions.create("admin").unwrap().token;
    let service = GatewayService::new(
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        target_adapter,
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        sessions,
    );
    let shutdown = Arc::new(ShutdownRuntime::new());
    let app = build_router_with_runtime_and_security(
        service,
        Arc::clone(&shutdown),
        RestSecurityConfig::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(server::serve(
        listener,
        app,
        Arc::clone(&shutdown),
        drain_timeout,
    ));

    GracefulShutdownHarness {
        addr,
        client: Client::new(),
        token,
        shutdown,
        handle,
    }
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

    let request = {
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
    };

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

    let request = {
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
    };

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

// ============================================================================
// Session Lifecycle Tests
// ============================================================================

/// POST /api/v1/sessions with valid Basic auth creates a session and returns
/// the token, idle timeout, and GMP version.
#[tokio::test]
async fn create_session_valid_credentials() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

    let response = client
        .post(format!("http://{addr}/api/v1/sessions"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0") // admin:secret
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let json = response.json::<serde_json::Value>().await.unwrap();
    let token = json["sessionToken"].as_str().unwrap();
    assert!(token.starts_with("gvm_sess_"));
    assert_eq!(location, format!("/api/v1/sessions/{token}"));
    assert_eq!(json["expiresIn"], 300);
    assert_eq!(json["gmpVersion"], "22.7");

    handle.abort();
}

/// POST /api/v1/sessions without an Authorization header returns 401.
#[tokio::test]
async fn create_session_missing_auth() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;

    let response = Client::new()
        .post(format!("http://{addr}/api/v1/sessions"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    handle.abort();
}

/// GET /api/v1/sessions/{token} returns session details for an active session.
#[tokio::test]
async fn get_session_returns_details() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

    // Create a session first.
    let create_resp = client
        .post(format!("http://{addr}/api/v1/sessions"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .unwrap();
    let token = create_resp.json::<serde_json::Value>().await.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();

    // Inspect the session.
    let response = client
        .get(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["sessionToken"], token);
    assert_eq!(json["user"], "admin");
    assert_eq!(json["state"], "active");
    assert!(json["createdAt"].as_str().unwrap().ends_with('Z'));
    assert!(json["expiresIn"].as_i64().unwrap() > 0);

    handle.abort();
}

/// GET /api/v1/sessions/{unknown} returns 404.
#[tokio::test]
async fn get_session_not_found() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;

    let response = Client::new()
        .get(format!("http://{addr}/api/v1/sessions/nonexistent-token"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    handle.abort();
}

/// DELETE /api/v1/sessions/{token} closes the session. Subsequent GET returns 404.
#[tokio::test]
async fn delete_session_closes_and_invalidates() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

    // Create a session.
    let create_resp = client
        .post(format!("http://{addr}/api/v1/sessions"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .unwrap();
    let token = create_resp.json::<serde_json::Value>().await.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();

    // Delete the session.
    let response = client
        .delete(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Confirm it's gone.
    let response = client
        .get(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    handle.abort();
}

/// Session reaper removes expired sessions so that GET returns 404.
#[tokio::test]
async fn session_reaper_cleans_up_expired_sessions() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Use a very short idle timeout (0 seconds = immediately expired).
    let sessions = Arc::new(SessionManager::new(0));
    let arc_adapter: Arc<StaticGvmdAdapter> = Arc::new(adapter);
    let reaper = SessionReaper::new(Arc::clone(&sessions), arc_adapter.clone());
    let service = GatewayService::new(
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter.clone(),
        arc_adapter,
        sessions,
    );

    // Spawn the reaper with a very short interval.
    let reaper = reaper.spawn_with_interval(Duration::from_millis(20));
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();

    // Create a session — it's immediately idle-expired due to timeout=0.
    let create_resp = client
        .post(format!("http://{addr}/api/v1/sessions"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let token = create_resp.json::<serde_json::Value>().await.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();

    // Wait for the reaper to sweep.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The session should now be gone.
    let response = client
        .get(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    reaper.abort();
    handle.abort();
}

/// DELETE /api/v1/sessions/{unknown} returns 404.
#[tokio::test]
async fn delete_session_not_found() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;

    let response = Client::new()
        .delete(format!("http://{addr}/api/v1/sessions/nonexistent-token"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    handle.abort();
}

// ============================================================================
// OpenAPI Contract Tests
// ============================================================================

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
    let sessions_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/sessions.yaml")).unwrap();
    let targets_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();
    let tasks_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/tasks.yaml")).unwrap();
    let reports_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/reports.yaml")).unwrap();
    let results_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/results.yaml")).unwrap();
    let alerts_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/alerts.yaml")).unwrap();
    let schedules_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/schedules.yaml")).unwrap();
    let credentials_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/credentials.yaml")).unwrap();
    let port_lists_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/port-lists.yaml")).unwrap();
    let feeds_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/feeds.yaml")).unwrap();
    let scan_configs_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/scan-configs.yaml")).unwrap();
    let scanners_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/scanners.yaml")).unwrap();
    let common_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/common.yaml")).unwrap();

    let docs = SpecDocs {
        generated: &json,
        system: &system_spec,
        sessions: &sessions_spec,
        targets: &targets_spec,
        tasks: &tasks_spec,
        reports: &reports_spec,
        results: &results_spec,
        alerts: &alerts_spec,
        schedules: &schedules_spec,
        credentials: &credentials_spec,
        port_lists: &port_lists_spec,
        feeds: &feeds_spec,
        scan_configs: &scan_configs_spec,
        scanners: &scanners_spec,
        common: &common_spec,
    };

    assert_eq!(json["servers"], root_spec["servers"]);
    assert_eq!(json["security"], root_spec["security"]);
    assert_eq!(
        path_names(&json),
        BTreeSet::from([
            "/health",
            "/alerts",
            "/alerts/{id}",
            "/credential-stores",
            "/credentials",
            "/credentials/{id}",
            "/feeds",
            "/feeds/sync",
            "/openapi.json",
            "/port-lists",
            "/port-lists/{id}",
            "/ready",
            "/reports",
            "/reports/{id}",
            "/reports/{id}/closed-cves",
            "/reports/{id}/errors",
            "/reports/{id}/results",
            "/reports/{id}/tls-certificates",
            "/reports/{id}/vulnerabilities",
            "/results",
            "/results/{id}",
            "/scan-configs",
            "/scan-configs/{id}",
            "/scanners",
            "/scanners/{id}",
            "/schedules",
            "/schedules/{id}",
            "/sessions",
            "/sessions/{token}",
            "/targets",
            "/targets/{id}",
            "/tasks",
            "/tasks/{id}",
            "/tasks/{id}/start",
            "/tasks/{id}/stop",
            "/tasks/{id}/resume",
            "/timezones",
            "/version",
        ])
    );

    let checks = [
        ("/health", "get", DocName::System, "/health"),
        ("/ready", "get", DocName::System, "/ready"),
        ("/version", "get", DocName::System, "/version"),
        ("/openapi.json", "get", DocName::System, "/openapi.json"),
        ("/sessions", "post", DocName::Sessions, "/sessions"),
        (
            "/sessions/{token}",
            "get",
            DocName::Sessions,
            "/sessions/{token}",
        ),
        (
            "/sessions/{token}",
            "delete",
            DocName::Sessions,
            "/sessions/{token}",
        ),
        ("/targets", "get", DocName::Targets, "/targets"),
        ("/targets", "post", DocName::Targets, "/targets"),
        ("/targets/{id}", "get", DocName::Targets, "/targets/{id}"),
        ("/targets/{id}", "put", DocName::Targets, "/targets/{id}"),
        ("/targets/{id}", "delete", DocName::Targets, "/targets/{id}"),
        ("/alerts", "get", DocName::Alerts, "/alerts"),
        ("/alerts", "post", DocName::Alerts, "/alerts"),
        ("/alerts/{id}", "get", DocName::Alerts, "/alerts/{id}"),
        ("/alerts/{id}", "put", DocName::Alerts, "/alerts/{id}"),
        ("/alerts/{id}", "delete", DocName::Alerts, "/alerts/{id}"),
        ("/timezones", "get", DocName::Schedules, "/timezones"),
        ("/schedules", "get", DocName::Schedules, "/schedules"),
        ("/schedules", "post", DocName::Schedules, "/schedules"),
        (
            "/schedules/{id}",
            "get",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/schedules/{id}",
            "put",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/schedules/{id}",
            "delete",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/credential-stores",
            "get",
            DocName::Credentials,
            "/credential-stores",
        ),
        ("/credentials", "get", DocName::Credentials, "/credentials"),
        ("/credentials", "post", DocName::Credentials, "/credentials"),
        (
            "/credentials/{id}",
            "get",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        (
            "/credentials/{id}",
            "put",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        (
            "/credentials/{id}",
            "delete",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        ("/port-lists", "get", DocName::PortLists, "/port-lists"),
        ("/port-lists", "post", DocName::PortLists, "/port-lists"),
        (
            "/port-lists/{id}",
            "get",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        (
            "/port-lists/{id}",
            "put",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        (
            "/port-lists/{id}",
            "delete",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        ("/feeds", "get", DocName::Feeds, "/feeds"),
        ("/feeds/sync", "post", DocName::Feeds, "/feeds/sync"),
        ("/tasks", "get", DocName::Tasks, "/tasks"),
        ("/tasks", "post", DocName::Tasks, "/tasks"),
        ("/tasks/{id}", "get", DocName::Tasks, "/tasks/{id}"),
        ("/tasks/{id}", "put", DocName::Tasks, "/tasks/{id}"),
        ("/tasks/{id}", "delete", DocName::Tasks, "/tasks/{id}"),
        (
            "/tasks/{id}/start",
            "post",
            DocName::Tasks,
            "/tasks/{id}/start",
        ),
        (
            "/tasks/{id}/stop",
            "post",
            DocName::Tasks,
            "/tasks/{id}/stop",
        ),
        (
            "/tasks/{id}/resume",
            "post",
            DocName::Tasks,
            "/tasks/{id}/resume",
        ),
        ("/reports", "get", DocName::Reports, "/reports"),
        ("/reports/{id}", "get", DocName::Reports, "/reports/{id}"),
        ("/reports/{id}", "delete", DocName::Reports, "/reports/{id}"),
        (
            "/reports/{id}/results",
            "get",
            DocName::Reports,
            "/reports/{id}/results",
        ),
        (
            "/reports/{id}/vulnerabilities",
            "get",
            DocName::Reports,
            "/reports/{id}/vulnerabilities",
        ),
        (
            "/reports/{id}/tls-certificates",
            "get",
            DocName::Reports,
            "/reports/{id}/tls-certificates",
        ),
        (
            "/reports/{id}/errors",
            "get",
            DocName::Reports,
            "/reports/{id}/errors",
        ),
        (
            "/reports/{id}/closed-cves",
            "get",
            DocName::Reports,
            "/reports/{id}/closed-cves",
        ),
        ("/results", "get", DocName::Results, "/results"),
        ("/results/{id}", "get", DocName::Results, "/results/{id}"),
        (
            "/scan-configs",
            "get",
            DocName::ScanConfigs,
            "/scan-configs",
        ),
        (
            "/scan-configs",
            "post",
            DocName::ScanConfigs,
            "/scan-configs",
        ),
        (
            "/scan-configs/{id}",
            "get",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        (
            "/scan-configs/{id}",
            "put",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        (
            "/scan-configs/{id}",
            "delete",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        ("/scanners", "get", DocName::Scanners, "/scanners"),
        ("/scanners/{id}", "get", DocName::Scanners, "/scanners/{id}"),
    ];

    for (generated_path, method, curated_doc, curated_path) in checks {
        assert_operation_contract(&docs, generated_path, method, curated_doc, curated_path);
    }

    handle.abort();
}

#[derive(Clone, Copy)]
enum DocName {
    Generated,
    System,
    Sessions,
    Targets,
    Alerts,
    Schedules,
    Credentials,
    PortLists,
    Feeds,
    Tasks,
    ScanConfigs,
    Scanners,
    Reports,
    Results,
    Common,
}

struct SpecDocs<'a> {
    generated: &'a Value,
    system: &'a Value,
    sessions: &'a Value,
    targets: &'a Value,
    tasks: &'a Value,
    reports: &'a Value,
    results: &'a Value,
    alerts: &'a Value,
    schedules: &'a Value,
    credentials: &'a Value,
    port_lists: &'a Value,
    feeds: &'a Value,
    scan_configs: &'a Value,
    scanners: &'a Value,
    common: &'a Value,
}

fn assert_operation_contract(
    docs: &SpecDocs<'_>,
    generated_path: &str,
    method: &str,
    curated_doc: DocName,
    curated_path: &str,
) {
    let generated_op = effective_operation(docs.generated, generated_path, method);
    let curated_op = effective_operation(doc(docs, curated_doc), curated_path, method);
    let context = format!("{method} {generated_path}");

    assert_eq!(
        generated_op["operationId"], curated_op["operationId"],
        "operationId drift for {context}"
    );
    assert_eq!(
        generated_op["tags"], curated_op["tags"],
        "tags drift for {context}"
    );
    assert_eq!(
        generated_op["summary"], curated_op["summary"],
        "summary drift for {context}"
    );

    compare_parameters(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_request_body(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_responses(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
}

fn compare_parameters(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_params = generated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let curated_params = curated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_params
        .iter()
        .map(|parameter| parameter_key(docs, generated_doc, parameter))
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_params
        .iter()
        .map(|parameter| parameter_key(docs, curated_doc, parameter))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        generated_keys, curated_keys,
        "parameter set drift for {context}"
    );

    for key in generated_keys {
        let generated_parameter = generated_params
            .iter()
            .find(|parameter| parameter_key(docs, generated_doc, parameter) == key)
            .unwrap();
        let curated_parameter = curated_params
            .iter()
            .find(|parameter| parameter_key(docs, curated_doc, parameter) == key)
            .unwrap();

        let (generated_parameter_doc, generated_parameter) =
            resolve_ref(docs, generated_doc, generated_parameter);
        let (curated_parameter_doc, curated_parameter) =
            resolve_ref(docs, curated_doc, curated_parameter);

        assert_required_flag(
            generated_parameter.get("required"),
            curated_parameter.get("required"),
            &format!("{context} parameter {key} required"),
        );

        compare_schema_like(
            docs,
            generated_parameter_doc,
            generated_parameter.get("schema").unwrap_or(&Value::Null),
            curated_parameter_doc,
            curated_parameter.get("schema").unwrap_or(&Value::Null),
            &format!("{context} parameter {key} schema"),
        );
    }
}

fn compare_request_body(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_body = generated_op
        .get("requestBody")
        .filter(|value| !value.is_null());
    let curated_body = curated_op
        .get("requestBody")
        .filter(|value| !value.is_null());

    match (generated_body, curated_body) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            panic!("requestBody presence drift for {context}");
        }
        (Some(generated_body), Some(curated_body)) => {
            let (generated_body_doc, generated_body) =
                resolve_ref(docs, generated_doc, generated_body);
            let (curated_body_doc, curated_body) = resolve_ref(docs, curated_doc, curated_body);

            assert_required_flag(
                generated_body.get("required"),
                curated_body.get("required"),
                &format!("{context} requestBody required"),
            );

            let generated_content = generated_body["content"].as_object().unwrap();
            let curated_content = curated_body["content"].as_object().unwrap();
            assert_eq!(
                generated_content.keys().collect::<BTreeSet<_>>(),
                curated_content.keys().collect::<BTreeSet<_>>(),
                "requestBody content types drift for {context}"
            );

            for media_type in generated_content.keys() {
                compare_schema_like(
                    docs,
                    generated_body_doc,
                    &generated_content[media_type]["schema"],
                    curated_body_doc,
                    &curated_content[media_type]["schema"],
                    &format!("{context} requestBody {media_type} schema"),
                );
            }
        }
    }
}

fn compare_responses(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_responses = generated_op["responses"].as_object().unwrap();
    let curated_responses = curated_op["responses"].as_object().unwrap();
    let generated_statuses = generated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_statuses = curated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert!(
        generated_statuses.is_subset(&curated_statuses),
        "response status drift for {context}: generated={generated_statuses:?}, curated={curated_statuses:?}"
    );

    for status in generated_statuses {
        let (generated_response_doc, generated_response) =
            resolve_ref(docs, generated_doc, &generated_responses[status]);
        let (curated_response_doc, curated_response) =
            resolve_ref(docs, curated_doc, &curated_responses[status]);

        let generated_content = generated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let curated_content = curated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let generated_media_types = generated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let curated_media_types = curated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert!(
            generated_media_types.is_subset(&curated_media_types),
            "response content type drift for {context} {status}"
        );
        compare_headers(
            docs,
            generated_response_doc,
            generated_response.get("headers"),
            curated_response_doc,
            curated_response.get("headers"),
            &format!("{context} response {status} headers"),
        );

        for media_type in generated_media_types {
            compare_schema_like(
                docs,
                generated_response_doc,
                &generated_content[media_type]["schema"],
                curated_response_doc,
                &curated_content[media_type]["schema"],
                &format!("{context} response {status} {media_type} schema"),
            );
        }
    }
}

fn compare_headers(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_headers: Option<&Value>,
    curated_doc: DocName,
    curated_headers: Option<&Value>,
    context: &str,
) {
    let generated_headers = generated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let curated_headers = curated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert!(
        generated_keys.is_subset(&curated_keys),
        "response header drift for {context}: generated={generated_keys:?}, curated={curated_keys:?}"
    );

    for key in generated_keys {
        let (generated_header_doc, generated_header) =
            resolve_ref(docs, generated_doc, &generated_headers[key]);
        let (curated_header_doc, curated_header) =
            resolve_ref(docs, curated_doc, &curated_headers[key]);

        assert_required_flag(
            generated_header.get("required"),
            curated_header.get("required"),
            &format!("{context} {key} required"),
        );
        compare_schema_like(
            docs,
            generated_header_doc,
            generated_header.get("schema").unwrap_or(&Value::Null),
            curated_header_doc,
            curated_header.get("schema").unwrap_or(&Value::Null),
            &format!("{context} {key} schema"),
        );
    }
}

fn compare_schema_like(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated: &Value,
    curated_doc: DocName,
    curated: &Value,
    context: &str,
) {
    let (generated_doc, generated) = resolve_ref(docs, generated_doc, generated);
    let (curated_doc, curated) = resolve_ref(docs, curated_doc, curated);

    match (generated, curated) {
        (Value::Null, Value::Null) => {}
        (_, Value::Null) | (Value::Null, _) => panic!("schema presence drift for {context}"),
        (Value::Object(generated), Value::Object(curated)) => {
            for (key, curated_value) in curated {
                if matches!(
                    key.as_str(),
                    "description" | "example" | "examples" | "title"
                ) {
                    continue;
                }

                let generated_value = generated
                    .get(key)
                    .unwrap_or_else(|| panic!("missing `{key}` in {context}"));

                match key.as_str() {
                    "required" if curated_value.is_boolean() => assert_required_flag(
                        Some(generated_value),
                        Some(curated_value),
                        &format!("{context} required"),
                    ),
                    "required" => assert_required_items(
                        generated_value,
                        curated_value,
                        &format!("{context} required"),
                    ),
                    "enum" => assert_enum_subset(
                        generated_value,
                        curated_value,
                        &format!("{context} enum"),
                    ),
                    "minimum" | "exclusiveMinimum" | "minLength" | "minItems" | "minProperties" => {
                        assert_numeric_at_least(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    "maximum" | "exclusiveMaximum" | "maxLength" | "maxItems" | "maxProperties" => {
                        assert_numeric_at_most(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    _ => compare_schema_like(
                        docs,
                        generated_doc,
                        generated_value,
                        curated_doc,
                        curated_value,
                        &format!("{context}.{key}"),
                    ),
                }
            }
        }
        (Value::Array(generated), Value::Array(curated)) => {
            assert_eq!(
                generated.len(),
                curated.len(),
                "array length drift for {context}"
            );
            for (index, (generated_value, curated_value)) in
                generated.iter().zip(curated).enumerate()
            {
                compare_schema_like(
                    docs,
                    generated_doc,
                    generated_value,
                    curated_doc,
                    curated_value,
                    &format!("{context}[{index}]"),
                );
            }
        }
        _ => assert_eq!(generated, curated, "value drift for {context}"),
    }
}

fn assert_required_flag(generated: Option<&Value>, curated: Option<&Value>, context: &str) {
    let generated = generated.and_then(Value::as_bool).unwrap_or(false);
    let curated = curated.and_then(Value::as_bool).unwrap_or(false);
    assert!(generated || !curated, "required-flag drift for {context}");
}

fn assert_required_items(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_superset(&curated),
        "required items drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_enum_subset(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_subset(&curated),
        "enum drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_numeric_at_least(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated >= curated, "numeric drift for {context}");
}

fn assert_numeric_at_most(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated <= curated, "numeric drift for {context}");
}

fn parameter_key(docs: &SpecDocs<'_>, current_doc: DocName, parameter: &Value) -> String {
    let (_, parameter) = resolve_ref(docs, current_doc, parameter);
    format!(
        "{}:{}",
        parameter["in"].as_str().unwrap(),
        parameter["name"].as_str().unwrap()
    )
}

fn effective_operation(doc: &Value, path: &str, method: &str) -> Value {
    let mut operation = op(doc, path, method).clone();
    let mut parameters = Vec::new();

    if let Some(path_parameters) = doc["paths"][path]["parameters"].as_array() {
        parameters.extend(path_parameters.iter().cloned());
    }
    if let Some(operation_parameters) = operation["parameters"].as_array() {
        parameters.extend(operation_parameters.iter().cloned());
    }
    if !parameters.is_empty() {
        operation["parameters"] = Value::Array(parameters);
    }

    operation
}

fn resolve_ref<'a>(
    docs: &'a SpecDocs<'a>,
    mut current_doc: DocName,
    mut value: &'a Value,
) -> (DocName, &'a Value) {
    while let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let (next_doc, pointer) = parse_ref(current_doc, reference);
        current_doc = next_doc;
        value = doc(docs, current_doc)
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("missing ref target `{reference}`"));
    }

    (current_doc, value)
}

fn parse_ref(current_doc: DocName, reference: &str) -> (DocName, String) {
    let (doc_name, pointer) = reference.split_once('#').unwrap_or((reference, ""));
    let doc = match doc_name {
        "" => current_doc,
        "./common.yaml" => DocName::Common,
        "./system.yaml" => DocName::System,
        "./sessions.yaml" => DocName::Sessions,
        "./targets.yaml" => DocName::Targets,
        "./alerts.yaml" => DocName::Alerts,
        "./schedules.yaml" => DocName::Schedules,
        "./credentials.yaml" => DocName::Credentials,
        "./port-lists.yaml" => DocName::PortLists,
        "./feeds.yaml" => DocName::Feeds,
        "./tasks.yaml" => DocName::Tasks,
        "./reports.yaml" => DocName::Reports,
        "./results.yaml" => DocName::Results,
        "./scan-configs.yaml" => DocName::ScanConfigs,
        "./scanners.yaml" => DocName::Scanners,
        other => panic!("unsupported ref document `{other}`"),
    };

    let pointer = if pointer.is_empty() {
        String::new()
    } else {
        pointer.replace("~1", "/").replace("~0", "~")
    };

    (doc, pointer)
}

fn doc<'a>(docs: &'a SpecDocs<'a>, name: DocName) -> &'a Value {
    match name {
        DocName::Generated => docs.generated,
        DocName::System => docs.system,
        DocName::Sessions => docs.sessions,
        DocName::Targets => docs.targets,
        DocName::Alerts => docs.alerts,
        DocName::Schedules => docs.schedules,
        DocName::Credentials => docs.credentials,
        DocName::PortLists => docs.port_lists,
        DocName::Feeds => docs.feeds,
        DocName::Tasks => docs.tasks,
        DocName::Reports => docs.reports,
        DocName::Results => docs.results,
        DocName::ScanConfigs => docs.scan_configs,
        DocName::Scanners => docs.scanners,
        DocName::Common => docs.common,
    }
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
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/bad-gateway")
    );
    assert_eq!(json["code"], serde_json::json!("backend_unavailable"));
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
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/not-found")
    );
    assert_eq!(json["code"], serde_json::json!("not_found"));
    assert_eq!(json["title"], serde_json::json!("Not Found"));
    assert_eq!(json["status"], serde_json::json!(404));
    assert_eq!(json["instance"], serde_json::json!("/does-not-exist"));

    handle.abort();
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
async fn list_targets_accepts_request_scoped_basic_auth() {
    let harness = target_harness(|_| {}).await;
    let auth_count_before = harness
        .server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "authenticate")
        .count();

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["data"], serde_json::json!([]));

    let history = harness.server.command_history();
    assert!(
        history
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count()
            > auth_count_before
    );
    assert!(history
        .iter()
        .any(|record| record.command_name() == "get_targets"));

    // The existing persistent bearer session remains usable and unchanged.
    let bearer_response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(bearer_response.status(), StatusCode::OK);

    harness.shutdown().await;
}

#[tokio::test]
async fn malformed_basic_auth_on_protected_route_returns_401() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .header("Authorization", "Basic not-base64")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 401);

    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_missing_bearer_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_malformed_bearer_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .header("Authorization", "Bearer")
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_unknown_session_rejected() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth("gvm_sess_unknown")
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_expired_session_rejected() {
    let harness = target_harness(|_| {}).await;
    harness.sessions.expire(&harness.token).unwrap();

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_closed_session_rejected() {
    let harness = target_harness(|_| {}).await;
    harness.sessions.remove(&harness.token).unwrap();

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_problem_status(response, StatusCode::UNAUTHORIZED).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn protected_endpoint_valid_session_allowed() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    harness.shutdown().await;
}

#[tokio::test]
async fn cors_preflight_allowed_origin() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: vec!["https://ui.example".to_string()],
            rate_limit: RateLimitConfig::disabled(),
        },
    )
    .await;

    let response = harness
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{}/api/v1/targets", harness.addr),
        )
        .header("Origin", "https://ui.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://ui.example"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn cors_preflight_denied_origin() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: vec!["https://ui.example".to_string()],
            rate_limit: RateLimitConfig::disabled(),
        },
    )
    .await;

    let response = harness
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{}/api/v1/targets", harness.addr),
        )
        .header("Origin", "https://evil.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    harness.shutdown().await;
}

#[tokio::test]
async fn security_headers_present() {
    let harness = target_harness(|_| {}).await;

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_security_headers(&response);
    harness.shutdown().await;
}

#[tokio::test]
async fn over_limit_returns_429() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
        },
    )
    .await;

    let first = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().contains_key("retry-after"));
    let json = second.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], 429);
    harness.shutdown().await;
}

#[tokio::test]
async fn retry_after_header_present() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(1),
                subject_per_window: Some(100),
            },
        },
    )
    .await;

    let _ = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    let response = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0));
    harness.shutdown().await;
}

#[tokio::test]
async fn different_sessions_have_independent_subject_limits() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
        },
    )
    .await;
    let second_token = harness.create_connected_session("admin", "admin").await;

    let first = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);

    let first_again = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(first_again.status(), StatusCode::TOO_MANY_REQUESTS);

    harness.shutdown().await;
}

#[tokio::test]
async fn global_limit_applies_across_sessions() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(1),
                subject_per_window: Some(100),
            },
        },
    )
    .await;
    let second_token = harness.create_connected_session("admin", "admin").await;

    let first = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = harness
        .client
        .get(format!("http://{}/api/v1/targets", harness.addr))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    harness.shutdown().await;
}

#[tokio::test]
async fn session_creation_rate_limited_before_backend_work() {
    let harness = target_harness_with_security(
        |_| {},
        RestSecurityConfig {
            cors_allowed_origins: Vec::new(),
            rate_limit: RateLimitConfig {
                window_secs: 60,
                global_per_window: Some(10),
                subject_per_window: Some(1),
            },
        },
    )
    .await;

    let first = harness
        .client
        .post(format!("http://{}/api/v1/sessions", harness.addr))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let auth_count_after_first = harness
        .server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "authenticate")
        .count();

    let second = harness
        .client
        .post(format!("http://{}/api/v1/sessions", harness.addr))
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        harness
            .server
            .command_history()
            .iter()
            .filter(|record| record.command_name() == "authenticate")
            .count(),
        auth_count_after_first
    );

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
    sessions: Arc<SessionManager>,
    target_adapter: GvmdAdapter,
    server: MockGmpServer,
    handle: tokio::task::JoinHandle<()>,
}

impl TargetHarness {
    async fn create_connected_session(&self, user: &str, password: &str) -> String {
        let token = self.sessions.create(user).unwrap().token;
        self.target_adapter
            .connect_session(&token, user, password)
            .await
            .unwrap();
        token
    }

    async fn shutdown(self) {
        self.handle.abort();
        self.server.shutdown().await;
    }
}

async fn target_harness(seed: impl FnOnce(&ResourceStore) + Send + 'static) -> TargetHarness {
    target_harness_with_security(seed, RestSecurityConfig::default()).await
}

async fn target_harness_with_security(
    seed: impl FnOnce(&ResourceStore) + Send + 'static,
    security: RestSecurityConfig,
) -> TargetHarness {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_7)
        .unix_socket_auto()
        .seed(seed)
        .build()
        .await
        .unwrap();

    let target_adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
    let sessions = Arc::new(SessionManager::default());
    let service = GatewayService::new(
        Arc::new(StaticGvmdAdapter::ready("22.7")),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::new(target_adapter.clone()),
        Arc::clone(&sessions),
    );
    let token = service.session_manager().create("admin").unwrap().token;
    target_adapter
        .connect_session(&token, "admin", "admin")
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router_with_security(service, security);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TargetHarness {
        addr,
        client: Client::new(),
        token,
        sessions,
        target_adapter,
        server,
        handle,
    }
}

async fn assert_problem_status(response: reqwest::Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/problem+json"
    );
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["status"], serde_json::json!(status.as_u16()));
    assert!(json["code"].as_str().is_some());
    assert!(json["type"]
        .as_str()
        .unwrap()
        .starts_with("https://gvm-gateway.greenbone.net/errors/"));
}

fn assert_security_headers(response: &reqwest::Response) {
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}
