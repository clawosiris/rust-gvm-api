// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! RESTful API server for Greenbone Vulnerability Management (GVM).
//!
//! Provides a standards-compliant REST API on top of the GMP protocol,
//! built using the `gvm-client` crate from the rust-gvm project.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Returns the crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}
