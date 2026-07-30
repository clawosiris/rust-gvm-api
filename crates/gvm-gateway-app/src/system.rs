// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! System-oriented gateway use cases.

use gvm_gateway_domain::{
    Aggregates, AggregatesQuery, GatewayError, HealthStatus, ReadinessStatus, VersionInfo,
};

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

    /// Runs an aggregate query for an authenticated session.
    pub async fn get_aggregates(
        &self,
        session_token: &str,
        query: AggregatesQuery,
    ) -> Result<Aggregates, GatewayError> {
        self.execute_with_resource(
            "aggregates.get",
            session_token,
            "read",
            "aggregate",
            None,
            |session| async move { self.system.get_aggregates(&session.token, &query).await },
        )
        .await
    }
}
