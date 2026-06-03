// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared REST route auth classification.

use axum::http::Method;

/// Auth policy for a REST route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestRouteAuthPolicy {
    /// Public endpoint with no auth requirement.
    Public,
    /// Basic-auth-only session creation endpoint.
    SessionCreate,
    /// Bearer-only session lifecycle endpoint keyed by path token.
    SessionTokenPath,
    /// Protected endpoint that accepts bearer auth or request-scoped Basic auth.
    Protected,
}

/// Classifies a runtime REST path into its auth policy bucket.
pub(crate) fn classify_runtime_route(method: &Method, path: &str) -> Option<RestRouteAuthPolicy> {
    if matches!(path, "/health" | "/ready") {
        return Some(RestRouteAuthPolicy::Public);
    }

    if matches!(path, "/api/v1/version" | "/api/v1/openapi.json") {
        return Some(RestRouteAuthPolicy::Public);
    }

    if path == "/api/v1/sessions" && *method == Method::POST {
        return Some(RestRouteAuthPolicy::SessionCreate);
    }

    if path.starts_with("/api/v1/sessions/") {
        return Some(RestRouteAuthPolicy::SessionTokenPath);
    }

    if path.starts_with("/api/v1/") {
        return Some(RestRouteAuthPolicy::Protected);
    }

    None
}

/// Maps a served OpenAPI path back to the runtime path used by the router.
pub(crate) fn runtime_path_from_openapi_path(path: &str) -> String {
    match path {
        "/health" | "/ready" => path.to_string(),
        "/version" => "/api/v1/version".to_string(),
        "/openapi.json" => "/api/v1/openapi.json".to_string(),
        _ => format!("/api/v1{path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy};
    use axum::http::Method;

    #[test]
    fn classifies_public_routes() {
        assert_eq!(
            classify_runtime_route(&Method::GET, "/health"),
            Some(RestRouteAuthPolicy::Public)
        );
        assert_eq!(
            classify_runtime_route(&Method::GET, "/ready"),
            Some(RestRouteAuthPolicy::Public)
        );
        assert_eq!(
            classify_runtime_route(&Method::GET, "/api/v1/version"),
            Some(RestRouteAuthPolicy::Public)
        );
        assert_eq!(
            classify_runtime_route(&Method::GET, "/api/v1/openapi.json"),
            Some(RestRouteAuthPolicy::Public)
        );
    }

    #[test]
    fn classifies_session_routes() {
        assert_eq!(
            classify_runtime_route(&Method::POST, "/api/v1/sessions"),
            Some(RestRouteAuthPolicy::SessionCreate)
        );
        assert_eq!(
            classify_runtime_route(&Method::GET, "/api/v1/sessions/token"),
            Some(RestRouteAuthPolicy::SessionTokenPath)
        );
    }

    #[test]
    fn treats_non_session_api_routes_as_protected_by_default() {
        assert_eq!(
            classify_runtime_route(&Method::GET, "/api/v1/alerts"),
            Some(RestRouteAuthPolicy::Protected)
        );
        assert_eq!(
            classify_runtime_route(&Method::GET, "/api/v1/future-resource"),
            Some(RestRouteAuthPolicy::Protected)
        );
    }

    #[test]
    fn maps_openapi_paths_back_to_runtime_paths() {
        assert_eq!(runtime_path_from_openapi_path("/health"), "/health");
        assert_eq!(
            runtime_path_from_openapi_path("/version"),
            "/api/v1/version"
        );
        assert_eq!(
            runtime_path_from_openapi_path("/reports/{id}/export"),
            "/api/v1/reports/{id}/export"
        );
    }
}
