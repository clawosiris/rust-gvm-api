// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Browser documentation for the generated REST contract.

use axum::{
    http::header,
    response::{Html, IntoResponse, Response},
};

/// Redoc is pinned and bundled so the UI does not depend on a third-party CDN.
const REDOC_JS: &[u8] = include_bytes!("../assets/redoc.standalone.js");

/// The contract remains the runtime-generated document served by this gateway.
const REDOC_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GVM REST API documentation</title>
</head>
<body>
  <redoc spec-url="/api/v1/openapi.json"></redoc>
  <script src="/api/v1/docs/redoc.standalone.js" integrity="sha512-qvBFYTqc2cW6IcK+smxCrHVwP6q9c6rXOWWadH5be4qs1lXPHoZ24xTdY6rk6Kf5Wu+L/xoP6VbkJoPP+KyHEQ=="></script>
</body>
</html>
"#;

/// Serves interactive documentation backed by the generated OpenAPI contract.
pub(crate) async fn api_docs() -> Html<&'static str> {
    Html(REDOC_HTML)
}

/// Serves the repository-bundled Redoc JavaScript asset.
pub(crate) async fn redoc_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        REDOC_JS,
    )
        .into_response()
}
