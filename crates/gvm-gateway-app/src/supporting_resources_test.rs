// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use crate::test_support::*;
use gvm_gateway_domain::{GatewayError, SupportingResourceQuery};

/// CVE list endpoints must preserve the normalized pagination contract once an
/// authenticated session has been established.
#[tokio::test]
async fn service_list_cves_with_valid_session_preserves_query_pagination() {
    let service = create_test_service();
    let session = service.session_manager().create("admin").unwrap();

    let page = service
        .list_cves(
            &session.token,
            SupportingResourceQuery {
                filter_string: Some("name~CVE".to_string()),
                filter_id: None,
                page: 2,
                per_page: 10,
            },
        )
        .await
        .expect("cve list should succeed with a valid session");

    assert_eq!(page.pagination.page, 2);
    assert_eq!(page.pagination.per_page, 10);
    assert_eq!(page.pagination.total, 0);
    assert!(page.data.is_empty());
}

/// Item reads must reject unknown session tokens before invoking the
/// supporting-resource backend, even for non-UUID SecInfo identifiers.
#[tokio::test]
async fn service_get_cve_requires_valid_session() {
    let service = create_test_service();

    let result = service.get_cve("invalid-token", "CVE-2026-1000").await;

    assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
}
