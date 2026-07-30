// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Trashcan restore/empty handlers and OpenAPI transforms for the REST adapter.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use gvm_gateway_app::GatewayService;

use crate::{
    error::RestError,
    handler::validate_uuid,
    openapi::{problem_response, ResourceIdPathDoc},
    router::bearer_token,
};

/// Restores a trashed resource by identifier.
pub async fn restore(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.restore(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Empties the trashcan for the authenticated session.
pub async fn empty_trashcan(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.empty_trashcan(&session).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// OpenAPI transform for `POST /api/v1/trashcan/{id}/restore`.
pub(crate) fn restore_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("restoreFromTrashcan")
        .tag("Trashcan")
        .summary("Restore from trashcan")
        .description("Restores a resource from the trashcan by identifier.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Resource restored"));
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/trashcan`.
pub(crate) fn empty_trashcan_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("emptyTrashcan")
        .tag("Trashcan")
        .summary("Empty the trashcan")
        .description("Permanently deletes all resources currently in the trashcan.")
        .security_requirement("bearerAuth")
        .response_with::<204, (), _>(|response| response.description("Trashcan emptied"));
    problem_response::<401>(op, "Authentication required or session expired")
}
