// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Application use cases for the GVM gateway.

use std::sync::Arc;

use gvm_gateway_domain::{
    GatewayError, HealthStatus, ReadinessStatus, SessionManager, SystemPort, TargetPort,
    VersionInfo,
};

/// Application services exposed to adapters.
pub struct GatewayService<S, T> {
    system: Arc<S>,
    targets: Arc<T>,
    sessions: Arc<SessionManager>,
}

impl<S, T> GatewayService<S, T> {
    /// Creates a new service backed by the provided ports.
    pub fn new(system: Arc<S>, targets: Arc<T>) -> Self {
        Self {
            system,
            targets,
            sessions: Arc::new(SessionManager::default()),
        }
    }

    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }
}

impl<S, T> Clone for GatewayService<S, T> {
    fn clone(&self) -> Self {
        Self {
            system: Arc::clone(&self.system),
            targets: Arc::clone(&self.targets),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<S, T> GatewayService<S, T>
where
    S: SystemPort,
    T: TargetPort,
{
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

    /// Lists targets for an authenticated session.
    pub async fn list_targets(
        &self,
        session_token: &str,
        query: T::TargetQuery,
    ) -> Result<T::TargetPage, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.list_targets(&session.token, &query).await
    }

    /// Creates a new target for an authenticated session.
    pub async fn create_target(
        &self,
        session_token: &str,
        input: T::CreateTargetInput,
    ) -> Result<String, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.create_target(&session.token, input).await
    }

    /// Fetches a target for an authenticated session.
    pub async fn get_target(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<T::Target, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.get_target(&session.token, id).await
    }

    /// Modifies a target for an authenticated session.
    pub async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: T::ModifyTargetInput,
    ) -> Result<T::Target, GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.modify_target(&session.token, id, input).await
    }

    /// Deletes a target for an authenticated session.
    pub async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let session = self.sessions.touch(session_token)?;
        self.targets.delete_target(&session.token, id).await
    }
}
