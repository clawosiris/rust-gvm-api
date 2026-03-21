// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 clawosiris

//! gRPC API server for Greenbone Vulnerability Management (GVM).
//!
//! Provides a high-performance gRPC API with server-streaming support
//! on top of the GMP protocol, built using the `gvm-client` crate from the
//! rust-gvm project.

#![deny(unsafe_code)]
#![warn(missing_docs)]
