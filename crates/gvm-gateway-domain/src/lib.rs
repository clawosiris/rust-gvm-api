// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Domain types and ports for the GVM gateway.

mod agents;
mod alerts;
mod common;
mod credentials;
mod error;
mod feeds;
mod identity;
mod jobs;
#[cfg(test)]
#[path = "lib_test.rs"]
mod lib_test;
mod log_safety;
mod port_lists;
mod ports;
mod reports;
mod results;
mod scan_configs;
mod scanners;
mod schedules;
mod session;
mod specialized_targets;
mod supporting_resources;
mod system;
mod targets;
mod tasks;
mod time;

pub use agents::*;
pub use alerts::*;
pub use common::*;
pub use credentials::*;
pub use error::*;
pub use feeds::*;
pub use identity::*;
pub use jobs::*;
pub use log_safety::{hide_optional_value, hide_value, HiddenValue};
pub use port_lists::*;
pub use ports::*;
pub use reports::*;
pub use results::*;
pub use scan_configs::*;
pub use scanners::*;
pub use schedules::*;
pub use session::{
    Session, SessionCreated, SessionHold, SessionInfo, SessionLimits, SessionManager, SessionState,
    SessionTokenDigest, DEFAULT_MAX_GLOBAL_SESSIONS, DEFAULT_MAX_SESSIONS_PER_USER,
};
pub use specialized_targets::*;
pub use supporting_resources::*;
pub use system::*;
pub use targets::*;
pub use tasks::*;
pub use time::format_rfc3339;
