// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! REST adapter for the GVM gateway.

pub(crate) mod dto;
pub mod error;
pub mod openapi;
pub mod reports;
pub mod results;
pub mod router;
pub mod scan_configs;
pub mod scanners;
pub mod sessions;
pub(crate) mod system;
pub mod targets;
pub mod tasks;
