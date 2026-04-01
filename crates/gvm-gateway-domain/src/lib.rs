// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Domain types and ports for the GVM gateway.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Opaque authenticated session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    /// Session token.
    pub token: String,
    /// Authenticated user.
    pub user: String,
    /// Current state.
    pub state: SessionState,
}

/// Session lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Session is active.
    Active,
    /// Session has expired.
    Expired,
    /// Session has been closed.
    Closed,
}

#[derive(Clone, Debug)]
struct StoredSession {
    user: String,
    state: SessionState,
}

/// In-memory domain session registry.
#[derive(Clone, Debug, Default)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<String, StoredSession>>>,
}

impl SessionManager {
    /// Create a new active session.
    pub fn create(&self, user: impl Into<String>) -> Result<Session, GatewayError> {
        let user = user.into();
        let token = format!("gvm_sess_{}", Uuid::new_v4().simple());
        let session = StoredSession {
            user: user.clone(),
            state: SessionState::Active,
        };
        self.inner
            .lock()
            .map_err(|_| {
                GatewayError::BackendUnavailable("session registry unavailable".to_string())
            })?
            .insert(token.clone(), session);
        Ok(Session {
            token,
            user,
            state: SessionState::Active,
        })
    }

    /// Look up a session by token.
    pub fn get(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        let guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        Ok(guard.get(token).map(|stored| Session {
            token: token.to_string(),
            user: stored.user.clone(),
            state: stored.state.clone(),
        }))
    }

    /// Mark a session as recently used and require it to be active.
    pub fn touch(&self, token: &str) -> Result<Session, GatewayError> {
        match self.get(token)? {
            Some(session) if session.state == SessionState::Active => Ok(session),
            Some(_) => Err(GatewayError::Unauthorized("session expired".to_string())),
            None => Err(GatewayError::Unauthorized("missing session".to_string())),
        }
    }

    /// Expire an existing session.
    pub fn expire(&self, token: &str) -> Result<(), GatewayError> {
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let stored = guard
            .get_mut(token)
            .ok_or_else(|| GatewayError::Unauthorized("missing session".to_string()))?;
        stored.state = SessionState::Expired;
        Ok(())
    }

    /// Remove an existing session.
    pub fn remove(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        let removed = self
            .inner
            .lock()
            .map_err(|_| {
                GatewayError::BackendUnavailable("session registry unavailable".to_string())
            })?
            .remove(token);
        Ok(removed.map(|stored| Session {
            token: token.to_string(),
            user: stored.user,
            state: stored.state,
        }))
    }
}

/// Application-level errors surfaced by ports and use cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// Backend service is unavailable or unhealthy.
    BackendUnavailable(String),
    /// Resource or route was not found.
    NotFound(String),
    /// Request input was invalid.
    InvalidInput(String),
    /// Session or credentials were invalid.
    Unauthorized(String),
}

/// Port for system information needed by the gateway.
pub trait SystemPort: Send + Sync + 'static {
    /// Returns whether the backend is ready.
    fn readiness(&self) -> Result<ReadinessStatus, GatewayError>;

    /// Returns the GMP version string for the connected backend.
    fn gmp_version(&self) -> Result<String, GatewayError>;
}

/// Port for target CRUD operations.
#[async_trait]
pub trait TargetPort: Send + Sync + 'static {
    /// Query type accepted by the adapter.
    type TargetQuery: Send + Sync + 'static;
    /// Create-target command type accepted by the adapter.
    type CreateTargetInput: Send + 'static;
    /// Update-target command type accepted by the adapter.
    type ModifyTargetInput: Send + 'static;
    /// Target representation returned by the adapter.
    type Target: Send + 'static;
    /// Paginated target page returned by the adapter.
    type TargetPage: Send + 'static;

    /// List targets for the session.
    async fn list_targets(
        &self,
        session_token: &str,
        query: &Self::TargetQuery,
    ) -> Result<Self::TargetPage, GatewayError>;

    /// Create a new target.
    async fn create_target(
        &self,
        session_token: &str,
        input: Self::CreateTargetInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a target by identifier.
    async fn get_target(&self, session_token: &str, id: &str)
        -> Result<Self::Target, GatewayError>;

    /// Modify a target by identifier.
    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: Self::ModifyTargetInput,
    ) -> Result<Self::Target, GatewayError>;

    /// Delete a target by identifier.
    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;
}
