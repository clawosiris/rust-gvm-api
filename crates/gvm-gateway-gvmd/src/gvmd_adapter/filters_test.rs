// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::GatewayError;

use super::filters::{paged_slice, paginated_filter, paginated_filter_with_reserved_terms};

#[test]
fn paged_slice_treats_maximum_page_as_out_of_range() {
    // An extreme page must produce the normal empty out-of-range page instead
    // of overflowing the client-side fallback offset and wrapping to old data.
    assert!(paged_slice(vec!["first", "second"], u32::MAX, 1_000).is_empty());
}

#[test]
fn paginated_filter_appends_backend_paging_terms() {
    // GMP filter paging is one-based: page 3 with 25 rows starts at item 51.
    assert_eq!(
        paginated_filter(Some("report_id=abc"), Some("severity>5"), 3, 25),
        Ok(Some(
            "report_id=abc severity>5 first=51 rows=25".to_string()
        ))
    );
    assert_eq!(
        paginated_filter(None, Some("   "), 1, 10),
        Ok(Some("first=1 rows=10".to_string()))
    );
}

#[test]
fn paginated_filter_rejects_caller_pagination_terms() {
    // User filter fragments must not override backend pagination terms that
    // the gateway appends after validation.
    let result = paginated_filter(None, Some("severity>5 first=1"), 3, 25);

    assert!(matches!(
        result,
        Err(GatewayError::InvalidInput(detail))
            if detail == "filter contains reserved term 'first'"
    ));
}

#[test]
fn paginated_filter_rejects_endpoint_owned_scope_terms() {
    // Report-scoped endpoints add report_id themselves, so a caller filter
    // may not inject another report_id clause.
    let result = paginated_filter_with_reserved_terms(
        Some("report_id=abc"),
        Some("report_id=def severity>5"),
        1,
        25,
        &["report_id"],
    );

    assert!(matches!(
        result,
        Err(GatewayError::InvalidInput(detail))
            if detail == "filter contains reserved term 'report_id'"
    ));
}
