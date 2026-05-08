// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Domain session types and the in-memory session registry.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::GatewayError;

// ============================================================================
// Domain Value Objects
// ============================================================================

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

/// Full session details returned by inspection endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    /// Session token.
    pub token: String,
    /// Authenticated user.
    pub user: String,
    /// State label: "active", "expired", or "closed".
    pub state: String,
    /// Creation time (epoch seconds).
    pub created_at: u64,
    /// Last usage time (epoch seconds).
    pub last_used_at: u64,
    /// Remaining seconds until idle expiry (0 when expired/closed).
    pub expires_in: i64,
}

/// Result returned after creating a new session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCreated {
    /// Session token.
    pub token: String,
    /// Idle timeout in seconds.
    pub expires_in: u64,
    /// GMP protocol version.
    pub gmp_version: String,
}

// ============================================================================
// Session Manager
// ============================================================================

#[derive(Clone, Debug)]
struct StoredSession {
    user: String,
    state: SessionState,
    created_at: u64,
    last_used_at: u64,
}

/// In-memory domain session registry.
#[derive(Clone, Debug)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<String, StoredSession>>>,
    idle_timeout_secs: u64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout_secs: 300,
        }
    }
}

impl SessionManager {
    /// Create a session manager with a custom idle timeout.
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout_secs,
        }
    }

    /// Returns the configured idle timeout in seconds.
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    /// Create a new active session.
    pub fn create(&self, user: impl Into<String>) -> Result<Session, GatewayError> {
        let user = user.into();
        let token = format!("gvm_sess_{}", uuid::Uuid::new_v4().simple());
        let now = now_secs();
        let session = StoredSession {
            user: user.clone(),
            state: SessionState::Active,
            created_at: now,
            last_used_at: now,
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

    /// Return detailed session information for inspection (does not extend the
    /// idle timer).
    pub fn get_info(&self, token: &str) -> Result<SessionInfo, GatewayError> {
        let now = now_secs();
        let guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let stored = guard
            .get(token)
            .ok_or_else(|| GatewayError::NotFound("session not found".to_string()))?;

        let (state, expires_in) = match stored.state {
            SessionState::Active => {
                let elapsed = now.saturating_sub(stored.last_used_at);
                if elapsed >= self.idle_timeout_secs {
                    ("expired".to_string(), 0i64)
                } else {
                    let remaining = (self.idle_timeout_secs - elapsed) as i64;
                    ("active".to_string(), remaining)
                }
            }
            SessionState::Expired => ("expired".to_string(), 0),
            SessionState::Closed => ("closed".to_string(), 0),
        };

        Ok(SessionInfo {
            token: token.to_string(),
            user: stored.user.clone(),
            state,
            created_at: stored.created_at,
            last_used_at: stored.last_used_at,
            expires_in,
        })
    }

    /// Mark a session as recently used and require it to be active.
    pub fn touch(&self, token: &str) -> Result<Session, GatewayError> {
        let now = now_secs();
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let stored = guard
            .get_mut(token)
            .ok_or_else(|| GatewayError::Unauthorized("missing session".to_string()))?;

        match stored.state {
            SessionState::Active => {
                if now.saturating_sub(stored.last_used_at) >= self.idle_timeout_secs {
                    stored.state = SessionState::Expired;
                    return Err(GatewayError::Unauthorized("session expired".to_string()));
                }
                stored.last_used_at = now;
                Ok(Session {
                    token: token.to_string(),
                    user: stored.user.clone(),
                    state: SessionState::Active,
                })
            }
            _ => Err(GatewayError::Unauthorized("session expired".to_string())),
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

    /// Remove all sessions that have exceeded the idle timeout or are already
    /// in a non-active state.  Returns the tokens of the removed sessions so
    /// the caller can perform backend cleanup (e.g. disconnect) outside the
    /// lock.
    pub fn drain_expired(&self) -> Result<Vec<String>, GatewayError> {
        let now = now_secs();
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let mut expired_tokens = Vec::new();
        guard.retain(|token, stored| {
            let dominated = match stored.state {
                SessionState::Active => {
                    now.saturating_sub(stored.last_used_at) >= self.idle_timeout_secs
                }
                SessionState::Expired | SessionState::Closed => true,
            };
            if dominated {
                expired_tokens.push(token.clone());
            }
            !dominated
        });
        Ok(expired_tokens)
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

// ============================================================================
// Time Helpers
// ============================================================================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format epoch seconds as an RFC 3339 UTC timestamp string.
pub fn format_rfc3339(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = (epoch_secs / secs_per_day) as i64;
    let time_secs = epoch_secs % secs_per_day;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Civil date from days since epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // SessionManager tests
    // ------------------------------------------------------------------------

    #[test]
    fn session_manager_create_returns_active_session() {
        let manager = SessionManager::default();
        let session = manager.create("alice").unwrap();

        assert!(session.token.starts_with("gvm_sess_"));
        assert_eq!(session.user, "alice");
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn session_manager_get_returns_none_for_missing_token() {
        let manager = SessionManager::default();
        let result = manager.get("nonexistent").unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn session_manager_get_returns_session_by_token() {
        let manager = SessionManager::default();
        let session = manager.create("bob").unwrap();
        let found = manager.get(&session.token).unwrap();

        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.token, session.token);
        assert_eq!(found.user, "bob");
    }

    #[test]
    fn session_manager_touch_returns_active_session() {
        let manager = SessionManager::default();
        let session = manager.create("carol").unwrap();
        let touched = manager.touch(&session.token).unwrap();

        assert_eq!(touched.token, session.token);
        assert_eq!(touched.state, SessionState::Active);
    }

    #[test]
    fn session_manager_touch_fails_for_missing_token() {
        let manager = SessionManager::default();
        let result = manager.touch("missing");

        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[test]
    fn session_manager_touch_fails_for_expired_session() {
        let manager = SessionManager::default();
        let session = manager.create("dave").unwrap();
        manager.expire(&session.token).unwrap();

        let result = manager.touch(&session.token);
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[test]
    fn session_manager_expire_marks_session_expired() {
        let manager = SessionManager::default();
        let session = manager.create("eve").unwrap();
        manager.expire(&session.token).unwrap();

        let found = manager.get(&session.token).unwrap().unwrap();
        assert_eq!(found.state, SessionState::Expired);
    }

    #[test]
    fn session_manager_expire_fails_for_missing_token() {
        let manager = SessionManager::default();
        let result = manager.expire("missing");

        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    #[test]
    fn session_manager_remove_deletes_session() {
        let manager = SessionManager::default();
        let session = manager.create("frank").unwrap();
        let removed = manager.remove(&session.token).unwrap();

        assert!(removed.is_some());
        assert!(manager.get(&session.token).unwrap().is_none());
    }

    #[test]
    fn session_manager_remove_returns_none_for_missing() {
        let manager = SessionManager::default();
        let removed = manager.remove("missing").unwrap();

        assert!(removed.is_none());
    }

    #[test]
    fn session_manager_multiple_sessions_independent() {
        let manager = SessionManager::default();
        let session1 = manager.create("user1").unwrap();
        let session2 = manager.create("user2").unwrap();

        assert_ne!(session1.token, session2.token);
        manager.expire(&session1.token).unwrap();

        // session2 should still be active
        let touched = manager.touch(&session2.token).unwrap();
        assert_eq!(touched.state, SessionState::Active);
    }

    // ------------------------------------------------------------------------
    // SessionManager.get_info tests
    // ------------------------------------------------------------------------

    /// get_info returns full session details without extending the idle timer.
    #[test]
    fn session_manager_get_info_returns_details() {
        let manager = SessionManager::default();
        let session = manager.create("alice").unwrap();
        let info = manager.get_info(&session.token).unwrap();

        assert_eq!(info.token, session.token);
        assert_eq!(info.user, "alice");
        assert_eq!(info.state, "active");
        assert!(info.created_at > 0);
        assert!(info.last_used_at > 0);
        assert!(info.expires_in > 0);
    }

    /// get_info returns 'expired' for a manually expired session.
    #[test]
    fn session_manager_get_info_expired() {
        let manager = SessionManager::default();
        let session = manager.create("bob").unwrap();
        manager.expire(&session.token).unwrap();
        let info = manager.get_info(&session.token).unwrap();

        assert_eq!(info.state, "expired");
        assert_eq!(info.expires_in, 0);
    }

    /// get_info fails with NotFound for unknown tokens.
    #[test]
    fn session_manager_get_info_not_found() {
        let manager = SessionManager::default();
        let result = manager.get_info("missing");

        assert!(matches!(result, Err(GatewayError::NotFound(_))));
    }

    // ------------------------------------------------------------------------
    // SessionManager idle timeout tests
    // ------------------------------------------------------------------------

    /// touch auto-expires sessions past the idle timeout.
    #[test]
    fn session_manager_touch_auto_expires_on_idle_timeout() {
        let manager = SessionManager::new(0);
        let session = manager.create("charlie").unwrap();
        let result = manager.touch(&session.token);

        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    /// idle_timeout_secs returns the configured value.
    #[test]
    fn session_manager_idle_timeout_secs() {
        let manager = SessionManager::new(600);
        assert_eq!(manager.idle_timeout_secs(), 600);
        assert_eq!(SessionManager::default().idle_timeout_secs(), 300);
    }

    // ------------------------------------------------------------------------
    // SessionManager drain_expired tests
    // ------------------------------------------------------------------------

    /// drain_expired returns nothing when all sessions are active within timeout.
    #[test]
    fn session_manager_drain_expired_no_expired() {
        let manager = SessionManager::default();
        manager.create("alice").unwrap();
        manager.create("bob").unwrap();

        let drained = manager.drain_expired().unwrap();
        assert!(drained.is_empty());
    }

    /// drain_expired returns tokens of manually expired sessions and removes them.
    #[test]
    fn session_manager_drain_expired_manually_expired() {
        let manager = SessionManager::default();
        let s1 = manager.create("alice").unwrap();
        let s2 = manager.create("bob").unwrap();
        manager.expire(&s1.token).unwrap();

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 1);
        assert!(drained.contains(&s1.token));

        assert!(manager.get(&s1.token).unwrap().is_none());
        assert!(manager.get(&s2.token).unwrap().is_some());
    }

    /// drain_expired returns tokens of idle-expired sessions (timeout == 0).
    #[test]
    fn session_manager_drain_expired_idle_timeout() {
        let manager = SessionManager::new(0);
        let s1 = manager.create("alice").unwrap();
        let s2 = manager.create("bob").unwrap();

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 2);
        assert!(drained.contains(&s1.token));
        assert!(drained.contains(&s2.token));

        assert!(manager.get(&s1.token).unwrap().is_none());
        assert!(manager.get(&s2.token).unwrap().is_none());
    }

    /// drain_expired is idempotent: calling twice returns empty on the second call.
    #[test]
    fn session_manager_drain_expired_idempotent() {
        let manager = SessionManager::new(0);
        manager.create("alice").unwrap();

        let first = manager.drain_expired().unwrap();
        assert_eq!(first.len(), 1);

        let second = manager.drain_expired().unwrap();
        assert!(second.is_empty());
    }

    /// drain_expired includes Closed sessions.
    #[test]
    fn session_manager_drain_expired_includes_closed() {
        let manager = SessionManager::default();
        let session = manager.create("alice").unwrap();
        manager.expire(&session.token).unwrap();

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 1);
    }

    // ------------------------------------------------------------------------
    // format_rfc3339 tests
    // ------------------------------------------------------------------------

    /// Unix epoch formats correctly.
    #[test]
    fn format_rfc3339_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    /// Known timestamp formats correctly.
    #[test]
    fn format_rfc3339_known_date() {
        // 2026-05-04T12:00:00Z = 1_777_896_000
        assert_eq!(format_rfc3339(1_777_896_000), "2026-05-04T12:00:00Z");
    }
}
