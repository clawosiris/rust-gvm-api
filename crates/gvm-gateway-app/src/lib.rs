// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

use std::sync::Arc;

use gvm_gateway_domain::{GatewayError, HealthStatus, ReadinessStatus, SystemPort, VersionInfo};

/// System-focused application services exposed to adapters.
pub struct SystemService<P> {
    port: Arc<P>,
}

impl<P> SystemService<P> {
    /// Creates a new service backed by the provided port.
    pub fn new(port: Arc<P>) -> Self {
        Self { port }
    }
}

impl<P> Clone for SystemService<P> {
    fn clone(&self) -> Self {
        Self {
            port: Arc::clone(&self.port),
        }
    }
}

impl<P> SystemService<P>
where
    P: SystemPort,
{
    /// Returns liveness information.
    pub fn health(&self) -> HealthStatus {
        HealthStatus { status: "ok" }
    }

    /// Returns readiness information.
    pub fn ready(&self) -> Result<ReadinessStatus, GatewayError> {
        self.port.readiness()
    }

    /// Returns version information.
    pub fn version(&self) -> Result<VersionInfo, GatewayError> {
        let gmp_version = self.port.gmp_version()?;
        Ok(VersionInfo {
            api_version: env!("CARGO_PKG_VERSION").to_string(),
            gmp_version,
        })
    }
}
