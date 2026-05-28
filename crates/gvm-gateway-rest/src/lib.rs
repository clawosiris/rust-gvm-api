// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! REST adapter for the GVM gateway.

pub mod alerts;
pub mod credentials;
pub(crate) mod dto;
pub mod error;
pub mod feeds;
pub mod identity;
pub mod openapi;
pub mod port_lists;
pub(crate) mod rate_limit;
pub mod reports;
pub mod results;
pub mod router;
pub mod scan_configs;
pub mod scanners;
pub mod schedules;
pub(crate) mod security;
pub mod sessions;
pub mod shutdown;
pub(crate) mod system;
pub mod targets;
pub mod tasks;
