// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Aggregate (statistics) DTOs, query parsing, handler, and OpenAPI transform.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{AggregatesQuery, GatewayError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{error::RestError, openapi::ok_json, openapi::problem_response, router::bearer_token};

/// OpenAPI documentation for the aggregate query parameters.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct AggregatesQueryParams {
    /// Backend resource type to aggregate over (required).
    #[serde(rename = "resourceType")]
    #[schemars(required)]
    resource_type: Option<String>,
    /// Optional group-by column.
    #[serde(rename = "groupColumn")]
    group_column: Option<String>,
    /// Optional comma-separated data columns.
    #[serde(rename = "dataColumns")]
    data_columns: Option<String>,
    /// Optional inline filter expression.
    filter: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AggregateSubgroup")]
pub(crate) struct AggregateSubgroupResponse {
    value: String,
    count: u32,
}

impl From<gvm_gateway_domain::AggregateSubgroup> for AggregateSubgroupResponse {
    fn from(subgroup: gvm_gateway_domain::AggregateSubgroup) -> Self {
        Self {
            value: subgroup.value,
            count: subgroup.count,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AggregateGroup")]
pub(crate) struct AggregateGroupResponse {
    value: String,
    count: u32,
    #[serde(rename = "cCount", skip_serializing_if = "Option::is_none")]
    c_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    subgroups: Vec<AggregateSubgroupResponse>,
}

impl From<gvm_gateway_domain::AggregateGroup> for AggregateGroupResponse {
    fn from(group: gvm_gateway_domain::AggregateGroup) -> Self {
        Self {
            value: group.value,
            count: group.count,
            c_count: group.c_count,
            text: group.text,
            subgroups: group
                .subgroups
                .into_iter()
                .map(AggregateSubgroupResponse::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "AggregateStats")]
pub(crate) struct AggregateStatsResponse {
    column: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mean: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sum: Option<f64>,
}

impl From<gvm_gateway_domain::AggregateStats> for AggregateStatsResponse {
    fn from(stats: gvm_gateway_domain::AggregateStats) -> Self {
        Self {
            column: stats.column,
            min: stats.min,
            max: stats.max,
            mean: stats.mean,
            sum: stats.sum,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Aggregates")]
pub(crate) struct AggregatesResponse {
    groups: Vec<AggregateGroupResponse>,
    #[serde(rename = "columnInfo", default, skip_serializing_if = "Vec::is_empty")]
    column_info: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overall: Option<AggregateStatsResponse>,
}

impl From<gvm_gateway_domain::Aggregates> for AggregatesResponse {
    fn from(aggregates: gvm_gateway_domain::Aggregates) -> Self {
        Self {
            groups: aggregates
                .groups
                .into_iter()
                .map(AggregateGroupResponse::from)
                .collect(),
            column_info: aggregates.column_info,
            overall: aggregates.overall.map(AggregateStatsResponse::from),
        }
    }
}

fn parse_aggregates_query(query: &str) -> Result<AggregatesQuery, GatewayError> {
    let mut resource_type = None;
    let mut group_column = None;
    let mut data_columns = None;
    let mut filter = None;

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "resourceType" => resource_type = Some(value.into_owned()),
            "groupColumn" => group_column = Some(value.into_owned()),
            "dataColumns" => data_columns = Some(value.into_owned()),
            "filter" => filter = Some(value.into_owned()),
            _ => {}
        }
    }

    let resource_type = resource_type
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| GatewayError::InvalidInput("resourceType is required".to_string()))?;

    Ok(AggregatesQuery {
        resource_type,
        group_column,
        data_columns,
        filter,
    })
}

/// Runs an aggregate query.
pub async fn get_aggregates(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match parse_aggregates_query(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.get_aggregates(&session, query).await {
        Ok(aggregates) => {
            (StatusCode::OK, Json(AggregatesResponse::from(aggregates))).into_response()
        }
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// OpenAPI transform for `GET /api/v1/aggregates`.
pub(crate) fn get_aggregates_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getAggregates")
        .tag("Aggregates")
        .summary("Run an aggregate query")
        .description(
            "Returns grouped counts and statistics for a backend resource type. \
             Requires `resourceType`; optionally scoped by `groupColumn`, `dataColumns`, and `filter`.",
        )
        .security_requirement("bearerAuth")
        .input::<Query<AggregatesQueryParams>>()
        .response_with::<200, Json<AggregatesResponse>, _>(ok_json("Aggregate query result"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}
