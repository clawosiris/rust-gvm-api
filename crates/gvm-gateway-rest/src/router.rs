// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Router construction for the REST adapter.

use std::sync::Arc;

use aide::{
    axum::{
        routing::{delete_with, get_with, post_with, put_with},
        ApiRouter,
    },
    openapi::OpenApi,
};
use axum::{
    extract::{Extension, OriginalUri, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch},
    Json, Router,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    AuthPort, ReportPort, ResultPort, ScanConfigPort, ScannerPort, SystemPort, TargetPort, TaskPort,
};
use serde_json::Value;

use crate::{
    error::RestError,
    openapi::{
        configure as configure_openapi, create_scan_config_docs, create_session_docs,
        create_target_docs, create_task_docs, delete_report_docs, delete_scan_config_docs,
        delete_session_docs, delete_target_docs, delete_task_docs, finalize_document,
        get_report_docs, get_report_results_docs, get_result_docs, get_scan_config_docs,
        get_scanner_docs, get_session_docs, get_target_docs, get_task_docs, health_docs,
        list_reports_docs, list_results_docs, list_scan_configs_docs, list_scanners_docs,
        list_targets_docs, list_tasks_docs, ready_docs, resume_task_docs, start_task_docs,
        stop_task_docs, update_scan_config_docs, update_target_docs, update_task_docs,
        version_docs,
    },
    reports::{delete_report, get_report, get_report_results, list_reports},
    results::{get_result, list_results},
    scan_configs::{
        create_scan_config, delete_scan_config, get_scan_config, list_scan_configs,
        update_scan_config,
    },
    scanners::{get_scanner, list_scanners},
    sessions::{create_session, delete_session, get_session},
    targets::{create_target, delete_target, get_target, list_targets, update_target},
    tasks::{
        create_task, delete_task, get_task, list_tasks, resume_task, start_task, stop_task,
        update_task,
    },
};

/// Builds the gateway router.
pub fn build_router<S, T, K, A, R, Re, Sc, Sn>(
    state: GatewayService<S, T, K, A, R, Re, Sc, Sn>,
) -> Router
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    let openapi = build_openapi::<S, T, K, A, R, Re, Sc, Sn>();
    let openapi_json =
        Arc::new(serde_json::to_string_pretty(&openapi).expect("generated OpenAPI must serialize"));

    documented_router::<S, T, K, A, R, Re, Sc, Sn>()
        .route("/api/v1/openapi.json", get(serve_openapi))
        .fallback(not_found)
        .layer(middleware::from_fn(trace_context_middleware))
        .with_state(state)
        .layer(Extension(openapi_json))
        .into()
}

/// Builds the generated OpenAPI document for the currently implemented routes.
pub(crate) fn build_openapi<S, T, K, A, R, Re, Sc, Sn>() -> Value
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    let mut api = OpenApi::default();
    aide::generate::extract_schemas(true);
    aide::generate::infer_responses(false);
    aide::generate::inferred_empty_response_status(204);

    let _ = documented_router::<S, T, K, A, R, Re, Sc, Sn>()
        .finish_api_with(&mut api, configure_openapi);
    finalize_document(serde_json::to_value(api).expect("generated OpenAPI must serialize"))
}

fn documented_router<S, T, K, A, R, Re, Sc, Sn>(
) -> ApiRouter<GatewayService<S, T, K, A, R, Re, Sc, Sn>>
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    ApiRouter::new()
        .api_route("/health", get_with(health, health_docs))
        .api_route("/ready", get_with(ready, ready_docs))
        .api_route("/api/v1/version", get_with(version, version_docs))
        // Session lifecycle
        .api_route(
            "/api/v1/sessions",
            post_with(create_session, create_session_docs),
        )
        .api_route(
            "/api/v1/sessions/{token}",
            get_with(get_session, get_session_docs),
        )
        .api_route(
            "/api/v1/sessions/{token}",
            delete_with(delete_session, delete_session_docs),
        )
        // Targets
        .api_route("/api/v1/targets", get_with(list_targets, list_targets_docs))
        .api_route(
            "/api/v1/targets",
            post_with(create_target, create_target_docs),
        )
        .route("/api/v1/targets", patch(method_not_allowed_collection))
        .api_route(
            "/api/v1/targets/{id}",
            get_with(get_target, get_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}",
            put_with(update_target, update_target_docs),
        )
        .api_route(
            "/api/v1/targets/{id}",
            delete_with(delete_target, delete_target_docs),
        )
        .route("/api/v1/targets/{id}", patch(method_not_allowed_item))
        // Tasks
        .api_route("/api/v1/tasks", get_with(list_tasks, list_tasks_docs))
        .api_route("/api/v1/tasks", post_with(create_task, create_task_docs))
        .route("/api/v1/tasks", patch(method_not_allowed_collection))
        .api_route("/api/v1/tasks/{id}", get_with(get_task, get_task_docs))
        .api_route(
            "/api/v1/tasks/{id}",
            put_with(update_task, update_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}",
            delete_with(delete_task, delete_task_docs),
        )
        .route("/api/v1/tasks/{id}", patch(method_not_allowed_item))
        .api_route(
            "/api/v1/tasks/{id}/start",
            post_with(start_task, start_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/stop",
            post_with(stop_task, stop_task_docs),
        )
        .api_route(
            "/api/v1/tasks/{id}/resume",
            post_with(resume_task, resume_task_docs),
        )
        // Reports
        .api_route("/api/v1/reports", get_with(list_reports, list_reports_docs))
        .api_route(
            "/api/v1/reports/{id}",
            get_with(get_report, get_report_docs),
        )
        .api_route(
            "/api/v1/reports/{id}",
            delete_with(delete_report, delete_report_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/results",
            get_with(get_report_results, get_report_results_docs),
        )
        // Results
        .api_route("/api/v1/results", get_with(list_results, list_results_docs))
        .api_route(
            "/api/v1/results/{id}",
            get_with(get_result, get_result_docs),
        )
        // Scan Configs
        .api_route(
            "/api/v1/scan-configs",
            get_with(list_scan_configs, list_scan_configs_docs),
        )
        .api_route(
            "/api/v1/scan-configs",
            post_with(create_scan_config, create_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            get_with(get_scan_config, get_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            put_with(update_scan_config, update_scan_config_docs),
        )
        .api_route(
            "/api/v1/scan-configs/{id}",
            delete_with(delete_scan_config, delete_scan_config_docs),
        )
        // Scanners
        .api_route(
            "/api/v1/scanners",
            get_with(list_scanners, list_scanners_docs),
        )
        .api_route(
            "/api/v1/scanners/{id}",
            get_with(get_scanner, get_scanner_docs),
        )
}

async fn serve_openapi(Extension(openapi_json): Extension<Arc<String>>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        (*openapi_json).clone(),
    )
        .into_response()
}

pub(crate) async fn health<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    Json(service.health()).into_response()
}

pub(crate) async fn ready<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    match service.ready() {
        Ok(readiness) if readiness.status == "ready" => {
            (StatusCode::OK, Json(readiness)).into_response()
        }
        Ok(readiness) => (StatusCode::SERVICE_UNAVAILABLE, Json(readiness)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/ready").into_response(),
    }
}

pub(crate) async fn version<S, T, K, A, R, Re, Sc, Sn>(
    State(service): State<GatewayService<S, T, K, A, R, Re, Sc, Sn>>,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    K: TaskPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
    Sc: ScanConfigPort,
    Sn: ScannerPort,
{
    match service.version() {
        Ok(version) => (StatusCode::OK, Json(version)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}

pub(crate) async fn method_not_allowed_collection(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
}

pub(crate) async fn method_not_allowed_item(uri: OriginalUri) -> Response {
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

pub(crate) fn bearer_token(
    headers: &HeaderMap,
) -> Result<String, gvm_gateway_domain::GatewayError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            gvm_gateway_domain::GatewayError::Unauthorized("missing bearer token".to_string())
        })?;

    value
        .strip_prefix("Bearer ")
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            gvm_gateway_domain::GatewayError::Unauthorized("missing bearer token".to_string())
        })
}
