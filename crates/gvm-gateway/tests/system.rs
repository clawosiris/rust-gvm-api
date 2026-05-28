mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    graceful_shutdown_harness, spawn_server, ControlledTargetAdapter, GracefulShutdownHarness,
};
use gvm_gateway_gvmd::StaticGvmdAdapter;
use http::StatusCode;
use reqwest::Client;
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
