// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 clawosiris

//! RESTful API server for Greenbone Vulnerability Management (GVM).
//!
//! Provides a standards-compliant REST API on top of the GMP protocol,
//! built using [`gvm-client`] from the rust-gvm project.

#![deny(unsafe_code)]
#![warn(missing_docs)]
