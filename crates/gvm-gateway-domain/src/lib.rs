// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 clawosiris

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Domain types and ports for the GVM gateway.

use serde::{Deserialize, Serialize};

/// Liveness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthStatus {
    /// Liveness state.
    pub status: &'static str,
}

/// Readiness state for the gateway process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessStatus {
    /// Readiness state.
    pub status: &'static str,
    /// Optional reason when not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// API and GMP version information.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    /// Gateway API version.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// GMP backend version.
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

/// Application-level errors surfaced by ports and use cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// Backend service is unavailable or unhealthy.
    BackendUnavailable(String),
    /// Resource or route was not found.
    NotFound(String),
}

/// Port for the minimal system information needed in Phase 1.
pub trait SystemPort: Send + Sync + 'static {
    /// Returns whether the backend is ready.
    fn readiness(&self) -> Result<ReadinessStatus, GatewayError>;

    /// Returns the GMP version string for the connected backend.
    fn gmp_version(&self) -> Result<String, GatewayError>;
}
