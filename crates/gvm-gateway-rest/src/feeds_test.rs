// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use serde_json::json;

use super::{FeedResponse, FeedType};
use gvm_gateway_domain::Feed;

fn feed_with_type(feed_type: &str) -> Feed {
    Feed {
        feed_type: feed_type.to_string(),
        name: "Feed".to_string(),
        version: "202606100000".to_string(),
        description: None,
        currently_syncing: false,
    }
}

#[test]
fn feed_type_deserialization_preserves_unknown_values() {
    // Feed catalogs can gain new families; clients should still receive the
    // exact backend value through the open-enum wrapper.
    let parsed: FeedType =
        serde_json::from_value(json!("COMMUNITY_DATA")).expect("feed type should parse");

    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        json!("COMMUNITY_DATA")
    );
}

#[test]
fn feed_response_preserves_known_and_unknown_types() {
    // Response mapping keeps the public `type` value verbatim for both the
    // current rust-gvm enum set and backend-added feed families.
    let known = serde_json::to_value(FeedResponse::from(feed_with_type("NVT")))
        .expect("feed response should serialize");
    let unknown = serde_json::to_value(FeedResponse::from(feed_with_type("COMMUNITY_DATA")))
        .expect("feed response should serialize");

    assert_eq!(known["type"], json!("NVT"));
    assert_eq!(unknown["type"], json!("COMMUNITY_DATA"));
}
