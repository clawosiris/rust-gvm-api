// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Router construction for the REST adapter.

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{GatewayError, SystemPort, TargetPort};

use crate::{
    error::RestError,
    targets::{validate_uuid, CreateTargetRequest, ModifyTargetRequest, TargetListQuery},
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
            "/api/v1/targets/{id}",
            get(get_target)
                .put(update_target)
                .delete(delete_target)
                .patch(method_not_allowed_item),
        )
        .fallback(not_found)
        .layer(middleware::from_fn(trace_context_middleware))
        .with_state(state)
}

async fn health<S, T>(State(service): State<GatewayService<S, T>>) -> impl IntoResponse
where
    S: SystemPort,
    T: TargetPort,
{
    Json(service.health())
}

async fn ready<S, T>(State(service): State<GatewayService<S, T>>) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    match service.ready() {
        Ok(readiness) if readiness.status == "ready" => {
            (StatusCode::OK, Json(readiness)).into_response()
        }
        Ok(readiness) => (StatusCode::SERVICE_UNAVAILABLE, Json(readiness)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/ready").into_response(),
    }
}

async fn version<S, T>(State(service): State<GatewayService<S, T>>) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    match service.version() {
        Ok(version) => (StatusCode::OK, Json(version)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}

async fn list_targets<S, T>(
    State(service): State<GatewayService<S, T>>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match TargetListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_targets(
            &session,
            gvm_gateway_domain::TargetQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(targets) => (StatusCode::OK, Json(targets)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

async fn create_target<S, T>(
    State(service): State<GatewayService<S, T>>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let request = match serde_json::from_slice::<CreateTargetRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response()
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.create_target(&session, input).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

async fn get_target<S, T>(
    State(service): State<GatewayService<S, T>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_target(&session, &id).await {
        Ok(target) => (StatusCode::OK, Json(target)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

async fn update_target<S, T>(
    State(service): State<GatewayService<S, T>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let request = match serde_json::from_slice::<ModifyTargetRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return RestError::from_gateway_error(
                GatewayError::InvalidInput(format!("invalid JSON body: {error}")),
                instance,
            )
            .into_response()
        }
    };
    let input = match request.validate() {
        Ok(input) => input,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.modify_target(&session, &id, input).await {
        Ok(target) => (StatusCode::OK, Json(target)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

async fn delete_target<S, T>(
    State(service): State<GatewayService<S, T>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.delete_target(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

async fn method_not_allowed_collection(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
}

async fn method_not_allowed_item(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
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

fn bearer_token(headers: &HeaderMap) -> Result<String, GatewayError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| GatewayError::Unauthorized("missing bearer token".to_string()))?;

    value
        .strip_prefix("Bearer ")
        .map(ToOwned::to_owned)
        .ok_or_else(|| GatewayError::Unauthorized("missing bearer token".to_string()))
}
