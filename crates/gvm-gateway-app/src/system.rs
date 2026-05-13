// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System-oriented gateway use cases.

use gvm_gateway_domain::{GatewayError, HealthStatus, ReadinessStatus, VersionInfo};

use crate::GatewayService;

impl GatewayService {
    /// Returns liveness information.
    pub fn health(&self) -> HealthStatus {
        HealthStatus { status: "ok" }
    }

    /// Returns readiness information.
    pub fn ready(&self) -> Result<ReadinessStatus, GatewayError> {
        self.system.readiness()
    }

    /// Returns version information.
    pub fn version(&self) -> Result<VersionInfo, GatewayError> {
        let gmp_version = self.system.gmp_version()?;
        Ok(VersionInfo {
            api_version: env!("CARGO_PKG_VERSION").to_string(),
            gmp_version,
        })
    }
}
