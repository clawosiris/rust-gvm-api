// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

#[test]
fn generic_resource_discriminators_are_explicit_and_open_strings() {
    // Domain serialization is shared by non-REST adapters as well, so it must
    // retain future backend strings and always expose each resource family.
    let config = GenericConfig {
        id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        name: "Future config".to_string(),
        comment: None,
        config_type: Some(42),
        usage_type: "future_usage".to_string(),
        in_use: false,
        writable: true,
    };

    let json = serde_json::to_value(config).expect("generic config should serialize");
    assert_eq!(json["usageType"], "future_usage");
    assert_eq!(json["type"], 42);
}
