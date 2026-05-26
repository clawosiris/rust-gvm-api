// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Router construction for the REST adapter.

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aide::{
    axum::{
        routing::{delete_with, get_with, post_with, put_with},
        ApiRouter,
    },
    openapi::OpenApi,
};
use axum::{
    extract::{Extension, OriginalUri, Request},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    error::RestError,
    openapi::{configure as configure_openapi, finalize_document},
    reports::{
        delete_report, delete_report_docs, get_report, get_report_docs, get_report_results,
        get_report_results_docs, list_reports, list_reports_docs,
    },
    results::{get_result, get_result_docs, list_results, list_results_docs},
    scan_configs::{
        create_scan_config, create_scan_config_docs, delete_scan_config, delete_scan_config_docs,
        get_scan_config, get_scan_config_docs, list_scan_configs, list_scan_configs_docs,
        update_scan_config, update_scan_config_docs,
    },
    scanners::{get_scanner, get_scanner_docs, list_scanners, list_scanners_docs},
    sessions::{
        create_session, create_session_docs, delete_session, delete_session_docs, get_session,
        get_session_docs,
    },
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

/// Builds the gateway router.
pub fn build_router(state: GatewayService) -> Router {
    build_router_with_security(state, RestSecurityConfig::default())
}

/// Builds the gateway router with explicit REST security middleware config.
pub fn build_router_with_security(state: GatewayService, security: RestSecurityConfig) -> Router {
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
            security_state,
            security_middleware,
        ))
        .with_state(state)
        .layer(Extension(openapi_json))
        .into()
}

/// REST security middleware configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RestSecurityConfig {
    /// Exact origins allowed for browser CORS requests. Empty means deny.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Rate-limit and backpressure settings.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// Fixed-window REST rate-limit settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Fixed window length in seconds.
    pub window_secs: u64,
    /// Maximum API requests across all sessions in one window. `None` disables
    /// the global limit.
    pub global_per_window: Option<u64>,
    /// Maximum API requests per auth subject in one window. `None` disables
    /// the subject/session limit.
    pub subject_per_window: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            global_per_window: Some(1_000),
            subject_per_window: Some(500),
        }
    }
}

impl RateLimitConfig {
    /// Disable all rate limits. Useful for tests that need only unrelated
    /// router behavior.
    pub fn disabled() -> Self {
        Self {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: None,
        }
    }
}

#[derive(Debug)]
struct SecurityRuntime {
    config: RestSecurityConfig,
    limiter: RateLimiter,
}

impl SecurityRuntime {
    fn new(config: RestSecurityConfig) -> Self {
        Self {
            limiter: RateLimiter::new(config.rate_limit.clone()),
            config,
        }
    }
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

pub(crate) async fn method_not_allowed_collection(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
}

pub(crate) async fn method_not_allowed_item(uri: OriginalUri) -> Response {
    RestError::method_not_allowed(uri.path()).into_response()
}

async fn not_found(request: Request) -> Response {
    RestError::not_found(request.uri().path()).into_response()
}

async fn security_middleware(
    security: axum::extract::State<Arc<SecurityRuntime>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    if is_cors_preflight(&request) {
        return cors_preflight_response(&security.config, request.headers(), &path);
    }

    if is_rate_limited_path(&path) {
        if let Some(retry_after) = security.limiter.check_request(&request) {
            let mut response = too_many_requests_response(&path, retry_after);
            apply_security_headers(response.headers_mut(), &path);
            apply_cors_headers(response.headers_mut(), &security.config, request.headers());
            tracing::warn!(
                target: "gvm_gateway_rest::security",
                security_event = "rate_limit.exceeded",
                path = %path,
                retry_after_secs = retry_after,
                "rate_limit_exceeded"
            );
            return response;
        }
    }

    let request_headers = request.headers().clone();
    let mut response = next.run(request).await;
    apply_security_headers(response.headers_mut(), &path);
    apply_cors_headers(response.headers_mut(), &security.config, &request_headers);
    response
}

fn is_cors_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request.headers().contains_key(header::ORIGIN)
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn cors_preflight_response(
    config: &RestSecurityConfig,
    headers: &HeaderMap,
    instance: &str,
) -> Response {
    let Some(origin) = allowed_origin(config, headers) else {
        let mut response = RestError::forbidden(
            "CORS origin is not allowed".to_string(),
            instance.to_string(),
        )
        .into_response();
        apply_security_headers(response.headers_mut(), instance);
        return response;
    };

    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,PUT,DELETE,OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization,Content-Type,Traceparent,Tracestate,Baggage"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    apply_security_headers(headers, instance);
    response
}

fn allowed_origin(config: &RestSecurityConfig, headers: &HeaderMap) -> Option<HeaderValue> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    if config
        .cors_allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        HeaderValue::from_str(origin).ok()
    } else {
        None
    }
}

fn apply_cors_headers(headers: &mut HeaderMap, config: &RestSecurityConfig, request: &HeaderMap) {
    if let Some(origin) = allowed_origin(config, request) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
}

fn apply_security_headers(headers: &mut HeaderMap, path: &str) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    if path.starts_with("/api/") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

fn is_rate_limited_path(path: &str) -> bool {
    path.starts_with("/api/v1/") && path != "/api/v1/openapi.json"
}

fn too_many_requests_response(instance: &str, retry_after_secs: u64) -> Response {
    let mut response = RestError::too_many_requests(
        format!("rate limit exceeded; retry after {retry_after_secs} seconds"),
        instance.to_string(),
    )
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

async fn trace_context_middleware(mut request: Request, next: Next) -> Response {
    let trace_headers = extract_trace_headers(request.headers());
    request.extensions_mut().insert(trace_headers.clone());

    let mut response = next.run(request).await;
    apply_trace_headers(response.headers_mut(), &trace_headers);
    response
}

async fn request_scoped_basic_auth_middleware(
    service: axum::extract::State<GatewayService>,
    mut request: Request,
    next: Next,
) -> Response {
    if !uses_request_scoped_basic_auth(&request) {
        return next.run(request).await;
    }

    let instance = request.uri().path().to_string();
    let (username, password) = match basic_credentials(request.headers()) {
        Ok(credentials) => credentials,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    let created = match service.create_session(&username, &password).await {
        Ok(created) => created,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let token = created.token;

    let bearer = match HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(value) => value,
        Err(_) => {
            let _ = service.delete_session(&token).await;
            return RestError::from_gateway_error(
                GatewayError::BackendUnavailable("failed to prepare request-scoped session".into()),
                instance,
            )
            .into_response();
        }
    };
    request.headers_mut().insert(header::AUTHORIZATION, bearer);

    let response = next.run(request).await;
    let response_was_successful = response.status().is_success();
    match service.delete_session(&token).await {
        Ok(()) => response,
        Err(error) if response_was_successful => {
            RestError::from_gateway_error(error, instance).into_response()
        }
        Err(_error) => response,
    }
}

fn uses_request_scoped_basic_auth(request: &Request) -> bool {
    if is_basic_auth(request.headers()).is_none() {
        return false;
    }

    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/ready" | "/api/v1/version" | "/api/v1/openapi.json"
    ) {
        return false;
    }

    // Keep the explicit session lifecycle contract unchanged: POST /sessions
    // uses Basic credentials to create a persistent bearer session, while
    // session inspection/deletion continue to operate on their path token.
    if (path == "/api/v1/sessions" && request.method() == Method::POST)
        || path.starts_with("/api/v1/sessions/")
    {
        return false;
    }

    is_protected_resource_path(path)
}

fn is_protected_resource_path(path: &str) -> bool {
    [
        "/api/v1/targets",
        "/api/v1/tasks",
        "/api/v1/reports",
        "/api/v1/results",
        "/api/v1/scan-configs",
        "/api/v1/scanners",
    ]
    .iter()
    .any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn is_basic_auth(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
}

fn basic_credentials(headers: &HeaderMap) -> Result<(String, String), GatewayError> {
    let encoded = is_basic_auth(headers)
        .ok_or_else(|| GatewayError::Unauthorized("expected Basic authentication".to_string()))?;

    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| GatewayError::Unauthorized("invalid Base64 in credentials".to_string()))?;
    let decoded_str = String::from_utf8(decoded)
        .map_err(|_| GatewayError::Unauthorized("invalid UTF-8 in credentials".to_string()))?;
    let (username, password) = decoded_str
        .split_once(':')
        .ok_or_else(|| GatewayError::Unauthorized("malformed Basic credentials".to_string()))?;

    if username.is_empty() {
        return Err(GatewayError::Unauthorized(
            "username must not be empty".to_string(),
        ));
    }

    Ok((username.to_string(), password.to_string()))
}

#[derive(Debug)]
struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<String, RateBucket>>,
}

#[derive(Clone, Debug)]
struct RateBucket {
    window_started_at: u64,
    count: u64,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check_request(&self, request: &Request) -> Option<u64> {
        let now = now_secs();
        if let Some(limit) = self.config.global_per_window {
            if let Some(retry_after) = self.check_key("global".to_string(), limit, now) {
                return Some(retry_after);
            }
        }

        if let Some(limit) = self.config.subject_per_window {
            return self.check_key(rate_limit_subject(request), limit, now);
        }

        None
    }

    fn check_key(&self, key: String, limit: u64, now: u64) -> Option<u64> {
        if limit == 0 {
            return Some(self.config.window_secs.max(1));
        }

        let window_secs = self.config.window_secs.max(1);
        let mut buckets = self.buckets.lock().ok()?;
        buckets.retain(|_, bucket| now.saturating_sub(bucket.window_started_at) < window_secs);
        let bucket = buckets.entry(key).or_insert_with(|| RateBucket {
            window_started_at: now,
            count: 0,
        });

        if now.saturating_sub(bucket.window_started_at) >= window_secs {
            bucket.window_started_at = now;
            bucket.count = 0;
        }

        if bucket.count >= limit {
            Some(
                window_secs
                    .saturating_sub(now.saturating_sub(bucket.window_started_at))
                    .max(1),
            )
        } else {
            bucket.count += 1;
            None
        }
    }
}

fn rate_limit_subject(request: &Request) -> String {
    let path = request.uri().path();
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if let Some(token) = auth.strip_prefix("Bearer ") {
        return format!("bearer:{}", stable_hash(token));
    }
    if let Some(credentials) = auth.strip_prefix("Basic ") {
        return format!("basic:{}", stable_hash(credentials));
    }
    if path == "/api/v1/sessions" {
        return "session-create:anonymous".to_string();
    }
    "anonymous".to_string()
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
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
