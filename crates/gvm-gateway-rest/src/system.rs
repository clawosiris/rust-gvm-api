// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System endpoint DTOs, handlers, and OpenAPI transforms for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{error::RestError, openapi::problem_response, shutdown::ShutdownRuntime};

// ============================================================================
// Response DTOs
// ============================================================================

/// Liveness state.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) enum HealthState {
    #[serde(rename = "ok")]
    Ok,
}

/// JSON body returned by `GET /health`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "HealthStatus")]
pub(crate) struct HealthStatusResponse {
    status: HealthState,
}

/// Readiness state.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) enum ReadinessState {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "notReady")]
    NotReady,
}

/// JSON body returned by `GET /ready`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "ReadinessStatus")]
pub(crate) struct ReadinessStatusResponse {
    status: ReadinessState,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// JSON body returned by `GET /api/v1/version`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "VersionInfo")]
pub(crate) struct VersionInfoResponse {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

// ============================================================================
// Handlers
// ============================================================================

pub(crate) async fn health(State(service): State<GatewayService>) -> Response {
    let _ = service.health();
    Json(HealthStatusResponse {
        status: HealthState::Ok,
    })
    .into_response()
}

pub(crate) async fn ready(
    State(service): State<GatewayService>,
    Extension(shutdown): Extension<std::sync::Arc<ShutdownRuntime>>,
) -> Response {
    if shutdown.is_shutting_down() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessStatusResponse {
                status: ReadinessState::NotReady,
                reason: Some("shutdown in progress".to_string()),
            }),
        )
            .into_response();
    }

    match service.ready() {
        Ok(readiness) if readiness.status == "ready" => (
            StatusCode::OK,
            Json(ReadinessStatusResponse {
                status: ReadinessState::Ready,
                reason: readiness.reason,
            }),
        )
            .into_response(),
        Ok(readiness) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessStatusResponse {
                status: ReadinessState::NotReady,
                reason: readiness.reason,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, "/ready").into_response(),
    }
}

pub(crate) async fn version(State(service): State<GatewayService>) -> Response {
    match service.version() {
        Ok(version) => (
            StatusCode::OK,
            Json(VersionInfoResponse {
                api_version: version.api_version,
                gmp_version: version.gmp_version,
            }),
        )
            .into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}

// ============================================================================
// OpenAPI transforms
// ============================================================================

/// OpenAPI transform for `GET /health`.
pub(crate) fn health_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.id("getHealth")
        .tag("System")
        .summary("Liveness probe")
        .description("Returns basic process liveness information.")
        .response_with::<200, Json<HealthStatusResponse>, _>(|response| {
            response.description("Service is alive")
        })
}

/// OpenAPI transform for `GET /ready`.
pub(crate) fn ready_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.id("getReadiness")
        .tag("System")
        .summary("Readiness probe")
        .description(
            "Indicates whether the service is ready to handle requests. Returns `503` while backend readiness is failing or graceful shutdown is draining in-flight requests.",
        )
        .response_with::<200, Json<ReadinessStatusResponse>, _>(|response| {
            response.description("Service is ready")
        })
        .response_with::<503, Json<ReadinessStatusResponse>, _>(|response| {
            response.description("Service is not ready")
        })
}

/// OpenAPI transform for `GET /api/v1/version`.
pub(crate) fn version_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getVersion")
        .tag("System")
        .summary("Get API and GMP version information")
        .description("Returns the gateway API version together with the connected GMP version.")
        .response_with::<200, Json<VersionInfoResponse>, _>(|response| {
            response.description("Version information")
        });

    problem_response::<502>(op, "Backend service unreachable or connection failed")
}
