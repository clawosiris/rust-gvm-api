mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{spawn_server, static_gateway_service_for_reaper};
use gvm_gateway_domain::SessionManager;
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::router::build_router;
use http::StatusCode;
use reqwest::Client;
use tokio::net::TcpListener;

#[tokio::test]
async fn create_session_valid_credentials() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

    let response = client
        .post(format!("http://{addr}/api/v1/sessions"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
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

#[tokio::test]
async fn get_session_returns_details() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

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

#[tokio::test]
async fn delete_session_closes_and_invalidates() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();

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

    let response = client
        .delete(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    handle.abort();
}

#[tokio::test]
async fn session_reaper_cleans_up_expired_sessions() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(SessionManager::new(0));
    let (service, reaper, _) = static_gateway_service_for_reaper(adapter, Arc::clone(&sessions));

    let reaper = reaper.spawn_with_interval(Duration::from_millis(20));
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
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

    tokio::time::sleep(Duration::from_millis(100)).await;

    let response = client
        .get(format!("http://{addr}/api/v1/sessions/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    reaper.abort();
    handle.abort();
}

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
