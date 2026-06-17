// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::{GetReportQuery, ReportResultsQuery};

#[test]
fn report_queries_decode_pagination_and_filter_values() {
    let report = GetReportQuery::try_from_query_string("page=2&perPage=30")
        .expect("encoded report query should parse");
    assert_eq!(report.page, 2);
    assert_eq!(report.per_page, 30);

    let results = ReportResultsQuery::try_from_query_string(
            "filter=severity%3E5+and+location~%22host%26port%3D443%22&filterId=123e4567%2De89b%2D12d3%2Da456%2D426614174000&page=2&perPage=10",
        )
        .expect("encoded filter should parse");
    assert_eq!(
        results.filter_string.as_deref(),
        Some("severity>5 and location~\"host&port=443\"")
    );
    assert_eq!(
        results.filter_id.as_deref(),
        Some("123e4567-e89b-12d3-a456-426614174000")
    );
    assert_eq!(results.page, 2);
    assert_eq!(results.per_page, 10);
}
