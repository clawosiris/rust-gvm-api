// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Router construction for the REST adapter.

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{GatewayError, SystemPort, TargetPort};

use crate::{
    error::RestError,
    system::{health, ready, version},
    targets::{
        create_target, delete_target, get_target, list_targets, method_not_allowed_collection,
        method_not_allowed_item, update_target,
    },
};

/// Builds the gateway router.
pub fn build_router<S, T>(state: GatewayService<S, T>) -> Router
where
    S: SystemPort,
    T: TargetPort,
{
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/version", get(version))
        .route(
            "/api/v1/targets",
            get(list_targets)
                .post(create_target)
                .patch(method_not_allowed_collection),
        )
        .route(
            "/api/v1/targets/:id",
            get(get_target)
                .put(update_target)
                .delete(delete_target)
                .patch(method_not_allowed_item),
        )
        .fallback(not_found)
        .layer(middleware::from_fn(trace_context_middleware))
        .with_state(state)
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

pub(crate) fn bearer_token(headers: &HeaderMap) -> Result<String, GatewayError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| GatewayError::Unauthorized("missing bearer token".to_string()))?;

    value
        .strip_prefix("Bearer ")
        .map(ToOwned::to_owned)
        .ok_or_else(|| GatewayError::Unauthorized("missing bearer token".to_string()))
}
