// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Helpers for formatting sensitive values in logs and diagnostics.

use std::fmt;

const REDACTED_VALUE: &str = "<redacted>";

/// Redacted marker for sensitive values in log and diagnostic output.
///
/// The marker does not retain a reference to the original value, so it can be
/// passed to `Debug`, `Display`, or tracing fields without carrying the secret.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct HiddenValue;

impl fmt::Debug for HiddenValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_VALUE)
    }
}

impl fmt::Display for HiddenValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_VALUE)
    }
}

/// Returns a redacted marker for a sensitive value.
pub fn hide_value<T: ?Sized>(_value: &T) -> HiddenValue {
    HiddenValue
}

/// Returns a redacted marker when an optional sensitive value is present.
pub fn hide_optional_value<T>(value: &Option<T>) -> Option<HiddenValue> {
    value.as_ref().map(hide_value)
}
