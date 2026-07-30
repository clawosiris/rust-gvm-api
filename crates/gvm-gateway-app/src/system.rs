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

    /// Restores a resource from the trashcan for an authenticated session.
    pub async fn restore(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "trashcan.restore",
            session_token,
            "restore",
            "trashcan",
            Some(id),
            |session| async move { self.system.restore(&session.token, id).await },
        )
        .await
    }

    /// Empties the trashcan for an authenticated session.
    pub async fn empty_trashcan(&self, session_token: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "trashcan.empty",
            session_token,
            "delete",
            "trashcan",
            None,
            |session| async move { self.system.empty_trashcan(&session.token).await },
        )
        .await
    }
}
