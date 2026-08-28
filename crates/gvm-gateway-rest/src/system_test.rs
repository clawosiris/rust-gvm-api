// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{TimezoneListResponse, TimezoneResponse};

#[test]
fn timezone_list_omits_absent_offsets() {
    // gvmd may return a bare timezone name like `UTC`, so the REST response
    // must preserve that compact shape instead of inventing a synthetic offset.
    let body = serde_json::to_value(TimezoneListResponse {
        data: vec![
            TimezoneResponse {
                name: "UTC".to_string(),
                offset: None,
            },
            TimezoneResponse {
                name: "Europe/Berlin".to_string(),
                offset: Some("+01:00".to_string()),
            },
        ],
    })
    .expect("timezone list should serialize");

    assert_eq!(
        body,
        json!({
            "data": [
                { "name": "UTC" },
                { "name": "Europe/Berlin", "offset": "+01:00" }
            ]
        })
    );
}
