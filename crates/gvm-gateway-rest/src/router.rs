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
    extract::{Extension, OriginalUri, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch},
    Router,
};
use gvm_gateway_app::GatewayService;
use serde_json::Value;

use crate::{
    alerts::{
        create_alert, create_alert_docs, delete_alert, delete_alert_docs, get_alert,
        get_alert_docs, list_alerts, list_alerts_docs, update_alert, update_alert_docs,
    },
    credentials::{
        create_credential, create_credential_docs, delete_credential, delete_credential_docs,
        get_credential, get_credential_docs, list_credential_stores, list_credential_stores_docs,
        list_credentials, list_credentials_docs, update_credential, update_credential_docs,
    },
    error::RestError,
    feeds::{list_feeds, list_feeds_docs, sync_feeds, sync_feeds_docs},
    openapi::{configure as configure_openapi, finalize_document},
    port_lists::{
        create_port_list, create_port_list_docs, delete_port_list, delete_port_list_docs,
        get_port_list, get_port_list_docs, list_port_lists, list_port_lists_docs, update_port_list,
        update_port_list_docs,
    },
    reports::{
        delete_report, delete_report_docs, get_report, get_report_closed_cves,
        get_report_closed_cves_docs, get_report_docs, get_report_errors, get_report_errors_docs,
        get_report_results, get_report_results_docs, get_report_tls_certificates,
        get_report_tls_certificates_docs, get_report_vulnerabilities,
        get_report_vulnerabilities_docs, list_reports, list_reports_docs,
    },
    results::{get_result, get_result_docs, list_results, list_results_docs},
    scan_configs::{
        create_scan_config, create_scan_config_docs, delete_scan_config, delete_scan_config_docs,
        get_scan_config, get_scan_config_docs, list_scan_configs, list_scan_configs_docs,
        update_scan_config, update_scan_config_docs,
    },
    scanners::{get_scanner, get_scanner_docs, list_scanners, list_scanners_docs},
    schedules::{
        create_schedule, create_schedule_docs, delete_schedule, delete_schedule_docs, get_schedule,
        get_schedule_docs, list_schedules, list_schedules_docs, list_timezones,
        list_timezones_docs, update_schedule, update_schedule_docs,
    },
    security::{request_scoped_basic_auth_middleware, security_middleware, SecurityRuntime},
    sessions::{
        create_session, create_session_docs, delete_session, delete_session_docs, get_session,
        get_session_docs,
    },
    shutdown::ShutdownRuntime,
    system::{health, health_docs, ready, ready_docs, version, version_docs},
    targets::{
        create_target, create_target_docs, delete_target, delete_target_docs, get_target,
        get_target_docs, list_targets, list_targets_docs, update_target, update_target_docs,
    },
    tasks::{
        create_task, create_task_docs, delete_task, delete_task_docs, get_task, get_task_docs,
        list_tasks, list_tasks_docs, resume_task, resume_task_docs, start_task, start_task_docs,
        stop_task, stop_task_docs, update_task, update_task_docs,
    },
};

pub use crate::rate_limit::RateLimitConfig;
pub use crate::security::RestSecurityConfig;

/// Builds the gateway router.
pub fn build_router(state: GatewayService) -> Router {
    build_router_with_runtime_and_security(
        state,
        Arc::new(ShutdownRuntime::default()),
        RestSecurityConfig::default(),
    )
}

/// Builds the gateway router with explicit REST security middleware config.
pub fn build_router_with_security(state: GatewayService, security: RestSecurityConfig) -> Router {
    build_router_with_runtime_and_security(state, Arc::new(ShutdownRuntime::default()), security)
}

/// Builds the gateway router with explicit shutdown and REST security runtime.
pub fn build_router_with_runtime_and_security(
    state: GatewayService,
    shutdown: Arc<ShutdownRuntime>,
    security: RestSecurityConfig,
) -> Router {
    let openapi = build_openapi();
    let openapi_json =
        Arc::new(serde_json::to_string_pretty(&openapi).expect("generated OpenAPI must serialize"));
    let request_scoped_auth_state = state.clone();
    let security_state = Arc::new(SecurityRuntime::new(security));

    documented_router()
        .route("/api/v1/openapi.json", get(serve_openapi))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            request_scoped_auth_state,
            request_scoped_basic_auth_middleware,
        ))
        .layer(middleware::from_fn(trace_context_middleware))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shutdown),
            shutdown_gate_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            security_state,
            security_middleware,
        ))
        .with_state(state)
        .layer(Extension(shutdown))
        .layer(Extension(openapi_json))
        .into()
}

/// Builds the generated OpenAPI document for the currently implemented routes.
pub(crate) fn build_openapi() -> Value {
    let mut api = OpenApi::default();
    aide::generate::extract_schemas(true);
    aide::generate::infer_responses(false);
    aide::generate::inferred_empty_response_status(204);

    let _ = documented_router().finish_api_with(&mut api, configure_openapi);
    finalize_document(serde_json::to_value(api).expect("generated OpenAPI must serialize"))
}

fn documented_router() -> ApiRouter<GatewayService> {
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
        // Alerts
        .api_route("/api/v1/alerts", get_with(list_alerts, list_alerts_docs))
        .api_route("/api/v1/alerts", post_with(create_alert, create_alert_docs))
        .route("/api/v1/alerts", patch(method_not_allowed_collection))
        .api_route("/api/v1/alerts/{id}", get_with(get_alert, get_alert_docs))
        .api_route(
            "/api/v1/alerts/{id}",
            put_with(update_alert, update_alert_docs),
        )
        .api_route(
            "/api/v1/alerts/{id}",
            delete_with(delete_alert, delete_alert_docs),
        )
        .route("/api/v1/alerts/{id}", patch(method_not_allowed_item))
        // Schedules
        .api_route(
            "/api/v1/timezones",
            get_with(list_timezones, list_timezones_docs),
        )
        .api_route(
            "/api/v1/schedules",
            get_with(list_schedules, list_schedules_docs),
        )
        .api_route(
            "/api/v1/schedules",
            post_with(create_schedule, create_schedule_docs),
        )
        .route("/api/v1/schedules", patch(method_not_allowed_collection))
        .api_route(
            "/api/v1/schedules/{id}",
            get_with(get_schedule, get_schedule_docs),
        )
        .api_route(
            "/api/v1/schedules/{id}",
            put_with(update_schedule, update_schedule_docs),
        )
        .api_route(
            "/api/v1/schedules/{id}",
            delete_with(delete_schedule, delete_schedule_docs),
        )
        .route("/api/v1/schedules/{id}", patch(method_not_allowed_item))
        // Credentials
        .api_route(
            "/api/v1/credential-stores",
            get_with(list_credential_stores, list_credential_stores_docs),
        )
        .api_route(
            "/api/v1/credentials",
            get_with(list_credentials, list_credentials_docs),
        )
        .api_route(
            "/api/v1/credentials",
            post_with(create_credential, create_credential_docs),
        )
        .route("/api/v1/credentials", patch(method_not_allowed_collection))
        .api_route(
            "/api/v1/credentials/{id}",
            get_with(get_credential, get_credential_docs),
        )
        .api_route(
            "/api/v1/credentials/{id}",
            put_with(update_credential, update_credential_docs),
        )
        .api_route(
            "/api/v1/credentials/{id}",
            delete_with(delete_credential, delete_credential_docs),
        )
        .route("/api/v1/credentials/{id}", patch(method_not_allowed_item))
        // Port Lists
        .api_route(
            "/api/v1/port-lists",
            get_with(list_port_lists, list_port_lists_docs),
        )
        .api_route(
            "/api/v1/port-lists",
            post_with(create_port_list, create_port_list_docs),
        )
        .route("/api/v1/port-lists", patch(method_not_allowed_collection))
        .api_route(
            "/api/v1/port-lists/{id}",
            get_with(get_port_list, get_port_list_docs),
        )
        .api_route(
            "/api/v1/port-lists/{id}",
            put_with(update_port_list, update_port_list_docs),
        )
        .api_route(
            "/api/v1/port-lists/{id}",
            delete_with(delete_port_list, delete_port_list_docs),
        )
        .route("/api/v1/port-lists/{id}", patch(method_not_allowed_item))
        // Feeds
        .api_route("/api/v1/feeds", get_with(list_feeds, list_feeds_docs))
        .route("/api/v1/feeds", patch(method_not_allowed_collection))
        .api_route("/api/v1/feeds/sync", post_with(sync_feeds, sync_feeds_docs))
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
        .api_route(
            "/api/v1/reports/{id}/vulnerabilities",
            get_with(get_report_vulnerabilities, get_report_vulnerabilities_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/tls-certificates",
            get_with(
                get_report_tls_certificates,
                get_report_tls_certificates_docs,
            ),
        )
        .api_route(
            "/api/v1/reports/{id}/errors",
            get_with(get_report_errors, get_report_errors_docs),
        )
        .api_route(
            "/api/v1/reports/{id}/closed-cves",
            get_with(get_report_closed_cves, get_report_closed_cves_docs),
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

async fn shutdown_gate_middleware(
    axum::extract::State(shutdown): axum::extract::State<Arc<ShutdownRuntime>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if should_bypass_shutdown_gate(&path) {
        return next.run(request).await;
    }

    let Some(_in_flight) = shutdown.try_track_request() else {
        tracing::info!(path, "shutdown: rejecting new request while draining");
        return RestError::service_unavailable(
            "The gateway is shutting down and no longer accepts new requests.",
            path,
        )
        .into_response();
    };

    next.run(request).await
}

fn should_bypass_shutdown_gate(path: &str) -> bool {
    matches!(path, "/health" | "/ready")
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn draining_router_rejects_new_non_probe_requests() {
        let service = GatewayService::new(
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_domain::SessionManager::default()),
        );
        let shutdown = Arc::new(ShutdownRuntime::new());
        let app = build_router_with_runtime_and_security(
            service,
            Arc::clone(&shutdown),
            RestSecurityConfig::default(),
        );

        assert!(shutdown.begin_shutdown());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn draining_router_keeps_readiness_probe_available() {
        let service = GatewayService::new(
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_gvmd::StaticGvmdAdapter::ready("22.7")),
            Arc::new(gvm_gateway_domain::SessionManager::default()),
        );
        let shutdown = Arc::new(ShutdownRuntime::new());
        let app = build_router_with_runtime_and_security(
            service,
            Arc::clone(&shutdown),
            RestSecurityConfig::default(),
        );

        assert!(shutdown.begin_shutdown());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
