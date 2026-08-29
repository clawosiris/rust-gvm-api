// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::ModifyPortListRequest;

#[test]
fn modify_port_list_request_preserves_rename() {
    // Regression coverage for #404: port-list PUT must accept and forward a
    // replacement name consistently with other rename-capable resources.
    let input = ModifyPortListRequest {
        name: Some("renamed ports".to_string()),
        comment: None,
        port_range: None,
    }
    .validate();

    assert_eq!(input.name.as_deref(), Some("renamed ports"));
}
