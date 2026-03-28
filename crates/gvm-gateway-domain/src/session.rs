// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session types and in-memory session registry.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::GatewayError;

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
pub(crate) struct StoredSession {
    pub(crate) user: String,
    pub(crate) state: SessionState,
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
