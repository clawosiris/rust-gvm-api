// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

mod alerts;
mod credentials;
mod feeds;
mod identity;
mod jobs;
mod port_lists;
mod reports;
mod results;
mod scan_configs;
mod scanners;
mod schedules;
mod service;
mod session;
mod supporting_resources;
mod system;
mod targets;
mod tasks;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use jobs::JobReaper;
pub use service::GatewayService;
pub use session::SessionReaper;
