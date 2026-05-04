// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! REST adapter for the GVM gateway.

pub mod error;
pub mod openapi;
pub mod router;
pub mod sessions;
pub mod targets;
