// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Generic time utilities.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time as seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format epoch seconds as an RFC 3339 UTC timestamp string.
pub fn format_rfc3339(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = (epoch_secs / secs_per_day) as i64;
    let time_secs = epoch_secs % secs_per_day;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Civil date from days since epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "time_test.rs"]
mod time_test;
