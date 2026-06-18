// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::*;

/// Unix epoch formats correctly.
#[test]
fn format_rfc3339_epoch() {
    assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
}

/// Known timestamp formats correctly.
#[test]
fn format_rfc3339_known_date() {
    // 2026-05-04T12:00:00Z = 1_777_896_000
    assert_eq!(format_rfc3339(1_777_896_000), "2026-05-04T12:00:00Z");
}
