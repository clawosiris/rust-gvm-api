// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session lifecycle use cases and the background session reaper.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use gvm_gateway_domain::{GatewayError, SessionCreated, SessionInfo};

use crate::GatewayService;

impl GatewayService {
    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<gvm_gateway_domain::SessionManager> {
        Arc::clone(&self.sessions)
    }

    // ------------------------------------------------------------------
    // Session lifecycle
    // ------------------------------------------------------------------

    /// Authenticates with the supplied credentials, creates a domain session,
    /// and establishes a backend connection bound to the new token.
    pub async fn create_session(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionCreated, GatewayError> {
        let session = self.sessions.create(username)?;
        if let Err(err) = self
            .auth
            .authenticate_session(&session.token, username, password)
            .await
        {
            // Roll back the domain session when backend auth fails.
            let _ = self.sessions.remove(&session.token);
            return Err(err);
        }
        let gmp_version = self.system.gmp_version()?;
        Ok(SessionCreated {
            token: session.token,
            expires_in: self.sessions.idle_timeout_secs(),
            gmp_version,
        })
    }

    /// Returns detailed session information without extending the idle timer.
    pub fn get_session(&self, token: &str) -> Result<SessionInfo, GatewayError> {
        self.sessions.get_info(token)
    }

    /// Closes and destroys a session, disconnecting the backend connection.
    pub async fn delete_session(&self, token: &str) -> Result<(), GatewayError> {
        let removed = self.sessions.remove(token)?;
        if removed.is_none() {
            return Err(GatewayError::NotFound("session not found".to_string()));
        }
        // Best-effort backend disconnect; ignore errors.
        let _ = self.auth.disconnect_session(token).await;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Session reaper
    // ------------------------------------------------------------------

    /// Spawns a background task that periodically drains idle-expired sessions
    /// and disconnects their backend connections.
    ///
    /// The returned `JoinHandle` can be aborted to stop the reaper (e.g. on
    /// server shutdown).  The default sweep interval is half the idle timeout
    /// so that expired sessions are reaped within one full timeout period.
    pub fn spawn_reaper(&self) -> JoinHandle<()> {
        let interval = Duration::from_secs(self.sessions.idle_timeout_secs() / 2);
        self.spawn_reaper_with_interval(interval)
    }

    /// Like [`spawn_reaper`](Self::spawn_reaper) but with an explicit sweep
    /// interval (useful for testing).
    pub fn spawn_reaper_with_interval(&self, interval: Duration) -> JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let auth = Arc::clone(&self.auth);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                let tokens = match sessions.drain_expired() {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::warn!(?err, "session reaper: drain_expired failed");
                        continue;
                    }
                };
                for token in &tokens {
                    if let Err(err) = auth.disconnect_session(token).await {
                        tracing::warn!(token, ?err, "session reaper: disconnect_session failed");
                    }
                }
                if !tokens.is_empty() {
                    tracing::info!(
                        count = tokens.len(),
                        "session reaper: cleaned up expired sessions"
                    );
                }
            }
        })
    }
}
