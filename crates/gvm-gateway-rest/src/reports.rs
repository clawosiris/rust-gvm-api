// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Report DTOs, request parsing, handlers, and response mapping for the REST adapter.

use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    AuthPort, GatewayError, GetReportOpts, ReportPort, ReportQuery, ResultPort, ResultQuery,
    SystemPort, TargetPort,
};

use crate::{error::RestError, router::bearer_token, targets::validate_uuid};

/// Parsed list-reports query from HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportListQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Optional filter identifier.
    pub filter_id: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportListQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut filter_string = None;
        let mut filter_id = None;
        let mut page = None;
        let mut per_page = None;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                "filter" => filter_string = Some(value.to_string()),
                "filterId" => {
                    validate_uuid("filterId", value)?;
                    filter_id = Some(value.to_string());
                }
                "page" => {
                    page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("page must be a positive integer".to_string())
                    })?);
                }
                "perPage" | "per_page" => {
                    per_page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                    })?);
                }
                _ => {}
            }
        }

        let page = page.unwrap_or(1);
        if page == 0 {
            return Err(GatewayError::InvalidInput(
                "page must be greater than or equal to 1".to_string(),
            ));
        }

        let per_page = per_page.unwrap_or(25).clamp(1, 1000);

        Ok(Self {
            filter_string,
            filter_id,
            page,
            per_page,
        })
    }
}

/// Parsed query parameters for GET /reports/{id} endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReportQuery {
    /// Whether to ignore pagination and return all results.
    pub ignore_pagination: bool,
}

impl GetReportQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Self {
        let mut ignore_pagination = false;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if key == "ignorePagination" {
                ignore_pagination = value == "true";
            }
        }

        Self { ignore_pagination }
    }
}

/// Parsed query for report results sub-resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportResultsQuery {
    /// Optional filter string.
    pub filter_string: Option<String>,
    /// Page number.
    pub page: u32,
    /// Page size.
    pub per_page: u32,
}

impl ReportResultsQuery {
    /// Parse query parameters from a raw query string.
    pub fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let mut filter_string = None;
        let mut page = None;
        let mut per_page = None;

        for pair in query.split('&').filter(|entry| !entry.is_empty()) {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                "filter" => filter_string = Some(value.to_string()),
                "page" => {
                    page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("page must be a positive integer".to_string())
                    })?);
                }
                "perPage" | "per_page" => {
                    per_page = Some(value.parse::<u32>().map_err(|_| {
                        GatewayError::InvalidInput("perPage must be a positive integer".to_string())
                    })?);
                }
                _ => {}
            }
        }

        let page = page.unwrap_or(1);
        if page == 0 {
            return Err(GatewayError::InvalidInput(
                "page must be greater than or equal to 1".to_string(),
            ));
        }

        let per_page = per_page.unwrap_or(25).clamp(1, 1000);

        Ok(Self {
            filter_string,
            page,
            per_page,
        })
    }
}

/// List reports handler.
pub async fn list_reports<S, T, A, R, Re>(
    State(service): State<GatewayService<S, T, A, R, Re>>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
{
    let instance = uri.path().to_string();
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ReportListQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .list_reports(
            &session,
            ReportQuery {
                filter_string: query.filter_string,
                filter_id: query.filter_id,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(reports) => (StatusCode::OK, Json(reports)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report handler.
pub async fn get_report<S, T, A, R, Re>(
    State(service): State<GatewayService<S, T, A, R, Re>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = GetReportQuery::try_from_query_string(uri.query().unwrap_or(""));

    match service
        .get_report(
            &session,
            &id,
            GetReportOpts {
                ignore_pagination: query.ignore_pagination,
            },
        )
        .await
    {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Delete report handler.
pub async fn delete_report<S, T, A, R, Re>(
    State(service): State<GatewayService<S, T, A, R, Re>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service.delete_report(&session, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}

/// Get report results handler.
pub async fn get_report_results<S, T, A, R, Re>(
    State(service): State<GatewayService<S, T, A, R, Re>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response
where
    S: SystemPort,
    T: TargetPort,
    A: AuthPort,
    R: ReportPort,
    Re: ResultPort,
{
    let instance = uri.path().to_string();
    if let Err(error) = validate_uuid("id", &id) {
        return RestError::from_gateway_error(error, instance).into_response();
    }
    let session = match bearer_token(&headers) {
        Ok(session) => session,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };
    let query = match ReportResultsQuery::try_from_query_string(uri.query().unwrap_or("")) {
        Ok(query) => query,
        Err(error) => return RestError::from_gateway_error(error, instance).into_response(),
    };

    match service
        .get_report_results(
            &session,
            &id,
            ResultQuery {
                filter_string: query.filter_string,
                filter_id: None,
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await
    {
        Ok(results) => (StatusCode::OK, Json(results)).into_response(),
        Err(error) => RestError::from_gateway_error(error, instance).into_response(),
    }
}
