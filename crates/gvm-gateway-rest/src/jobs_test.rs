// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::CreateReportExportRequestBody;

/// JSON export requests parse into the JSON export variant.
#[test]
fn parses_json_export_request_body() {
    let body: CreateReportExportRequestBody =
        serde_json::from_str(r#"{"format":"json"}"#).expect("body should parse");

    assert!(matches!(body, CreateReportExportRequestBody::Json(_)));
}
