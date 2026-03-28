// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System endpoint handlers for the REST adapter.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{SystemPort, TargetPort};

use crate::error::RestError;

pub(crate) async fn health<S, T>(State(service): State<GatewayService<S, T>>) -> impl IntoResponse
where
    S: SystemPort,
    T: TargetPort,
{
    Json(service.health())
}

pub(crate) async fn ready<S, T>(State(service): State<GatewayService<S, T>>) -> Response
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

pub(crate) async fn version<S, T>(State(service): State<GatewayService<S, T>>) -> Response
where
    S: SystemPort,
    T: TargetPort,
{
    match service.version() {
        Ok(version) => (StatusCode::OK, Json(version)).into_response(),
        Err(error) => RestError::from_gateway_error(error, "/api/v1/version").into_response(),
    }
}
