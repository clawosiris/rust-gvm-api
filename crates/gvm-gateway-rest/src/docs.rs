// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Browser documentation for the generated REST contract.

use aide::transform::TransformOperation;
use axum::response::Html;

/// Redoc is pinned and integrity-checked so the UI cannot drift independently
/// of a gateway release. The contract itself remains the runtime-generated
/// document served by this gateway.
const REDOC_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GVM REST API documentation</title>
</head>
<body>
  <redoc spec-url="/api/v1/openapi.json"></redoc>
  <script src="https://cdn.redoc.ly/redoc/v2.5.3/bundles/redoc.standalone.js" integrity="sha512-qvBFYTqc2cW6IcK+smxCrHVwP6q9c6rXOWWadH5be4qs1lXPHoZ24xTdY6rk6Kf5Wu+L/xoP6VbkJoPP+KyHEQ==" crossorigin="anonymous"></script>
</body>
</html>
"#;

/// Serves interactive documentation backed by the generated OpenAPI contract.
pub(crate) async fn api_docs() -> Html<&'static str> {
    Html(REDOC_HTML)
}

/// OpenAPI transform for `GET /api/v1/docs`.
pub(crate) fn api_docs_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.id("getApiDocumentation")
        .tag("System")
        .summary("Browse interactive API documentation")
        .description(
            "Returns a Redoc browser UI that loads the generated contract from `/api/v1/openapi.json`.",
        )
        .response_with::<200, Html<&'static str>, _>(|response| {
            response.description("Interactive API documentation")
        })
}
