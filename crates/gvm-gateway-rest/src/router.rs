// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 clawosiris

//! Router construction for the REST adapter.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use gvm_gateway_app::SystemService;
use gvm_gateway_domain::SystemPort;

use crate::error::RestError;

/// Builds the Phase 1 router.
pub fn build_router<P>(state: SystemService<P>) -> Router
where
    P: SystemPort,
{
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/version", get(version))
        .fallback(not_found)
        .layer(middleware::from_fn(trace_context_middleware))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn ready<P>(State(service): State<SystemService<P>>) -> Response
where
    P: SystemPort,
{
    match service.ready() {
        Ok(readiness) if readiness.status == "ready" => {
            (StatusCode::OK, Json(readiness)).into_response()
        }
        Ok(readiness) => (StatusCode::SERVICE_UNAVAILABLE, Json(readiness)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/ready").into_response(),
    }
}

async fn version<P>(State(service): State<SystemService<P>>) -> Response
where
    P: SystemPort,
{
    match service.version() {
        Ok(version) => (StatusCode::OK, Json(version)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}

async fn not_found(request: Request) -> Response {
    RestError::not_found(request.uri().path()).into_response()
}

async fn trace_context_middleware(mut request: Request, next: Next) -> Response {
    let trace_headers = extract_trace_headers(request.headers());
    request.extensions_mut().insert(trace_headers.clone());

    let mut response = next.run(request).await;
    apply_trace_headers(response.headers_mut(), &trace_headers);
    response
}

#[derive(Clone, Default)]
struct TraceHeaders {
    traceparent: Option<HeaderValue>,
    tracestate: Option<HeaderValue>,
    baggage: Option<HeaderValue>,
}

fn extract_trace_headers(headers: &HeaderMap) -> TraceHeaders {
    TraceHeaders {
        traceparent: headers.get("traceparent").cloned(),
        tracestate: headers.get("tracestate").cloned(),
        baggage: headers.get("baggage").cloned(),
    }
}

fn apply_trace_headers(headers: &mut HeaderMap, trace_headers: &TraceHeaders) {
    if let Some(value) = trace_headers.traceparent.clone() {
        headers.insert(HeaderName::from_static("traceparent"), value);
    }
    if let Some(value) = trace_headers.tracestate.clone() {
        headers.insert(HeaderName::from_static("tracestate"), value);
    }
    if let Some(value) = trace_headers.baggage.clone() {
        headers.insert(HeaderName::from_static("baggage"), value);
    }
}
