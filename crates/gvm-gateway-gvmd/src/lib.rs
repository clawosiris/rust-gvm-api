// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! gvmd adapter implementations for the gateway.

mod conversions;
mod gvmd_adapter;
mod static_adapter;

pub use gvmd_adapter::GvmdAdapter;
pub use static_adapter::StaticGvmdAdapter;
