use std::{net::SocketAddr, sync::Arc};

use gvm_gateway_app::SystemService;
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::router::build_router;
use http::StatusCode;
use reqwest::Client;
use tokio::net::TcpListener;

async fn spawn_server(adapter: StaticGvmdAdapter) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = SystemService::new(Arc::new(adapter));
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

#[tokio::test]
async fn health_returns_200() {
    let (addr, handle) = spawn_server(StaticGvmdAdapter::ready("22.7")).await;
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
    let (addr, handle) = spawn_server(StaticGvmdAdapter::ready("22.7")).await;
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
    let (addr, handle) =
        spawn_server(StaticGvmdAdapter::not_ready("gvmd unavailable", "22.7")).await;
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
    let (addr, handle) = spawn_server(StaticGvmdAdapter::ready("22.7")).await;
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
async fn trace_context_headers_propagated() {
    let (addr, handle) = spawn_server(StaticGvmdAdapter::ready("22.7")).await;
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
    let (addr, handle) =
        spawn_server(StaticGvmdAdapter::not_ready("backend offline", "22.7")).await;
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
    let (addr, handle) = spawn_server(StaticGvmdAdapter::ready("22.7")).await;
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
