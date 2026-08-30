// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System-oriented gateway use cases.

use gvm_gateway_domain::{GatewayError, HealthStatus, ReadinessStatus, Timezone, VersionInfo};

use crate::GatewayService;

impl GatewayService {
    /// Returns liveness information.
    pub fn health(&self) -> HealthStatus {
        HealthStatus { status: "ok" }
    }

    /// Returns readiness information.
    pub async fn ready(&self) -> Result<ReadinessStatus, GatewayError> {
        self.system.readiness().await
    }

    /// Returns version information.
    pub async fn version(&self) -> Result<VersionInfo, GatewayError> {
        let gmp_version = self.system.gmp_version().await?;
        Ok(VersionInfo {
            api_version: env!("CARGO_PKG_VERSION").to_string(),
            gmp_version,
        })
    }

    /// Lists backend timezones for an authenticated session.
    pub async fn list_timezones(&self, session_token: &str) -> Result<Vec<Timezone>, GatewayError> {
        self.execute_with_resource(
            "timezones.list",
            session_token,
            "list",
            "timezone",
            None,
            |session| async move { self.system.list_timezones(&session.token).await },
        )
        .await
    }
}
