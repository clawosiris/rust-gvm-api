// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Domain session types and the in-memory session registry.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};

use crate::{hide_value, time::now_secs, GatewayError};

// ============================================================================
// Domain Value Objects
// ============================================================================

/// Opaque authenticated session.
#[derive(Clone, Eq, PartialEq)]
pub struct Session {
    /// Session token.
    pub token: String,
    /// Authenticated user.
    pub user: String,
    /// Current state.
    pub state: SessionState,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("token", &hide_value(&self.token))
            .field("user", &self.user)
            .field("state", &self.state)
            .finish()
    }
}

/// Session lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Session is active.
    Active,
    /// Session has expired.
    Expired,
}

/// Full session details returned by inspection endpoints.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionInfo {
    /// Session token.
    pub token: String,
    /// Authenticated user.
    pub user: String,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Creation time (epoch seconds).
    pub created_at: u64,
    /// Last usage time (epoch seconds).
    pub last_used_at: u64,
    /// Remaining seconds until idle expiry (0 when expired).
    pub expires_in: i64,
}

impl fmt::Debug for SessionInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionInfo")
            .field("token", &hide_value(&self.token))
            .field("user", &self.user)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Result returned after creating a new session.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionCreated {
    /// Session token.
    pub token: String,
    /// Idle timeout in seconds.
    pub expires_in: u64,
    /// GMP protocol version.
    pub gmp_version: String,
}

impl fmt::Debug for SessionCreated {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCreated")
            .field("token", &hide_value(&self.token))
            .field("expires_in", &self.expires_in)
            .field("gmp_version", &self.gmp_version)
            .finish()
    }
}

/// Stable, non-reversible key derived from a bearer session token.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionTokenDigest([u8; 32]);

impl SessionTokenDigest {
    /// Build a digest key from a raw bearer token.
    pub fn from_token(token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Returns a short, non-secret identifier suitable for logs and tracing.
    pub fn safe_id(&self) -> String {
        format!("session:{}", hex_prefix(&self.0, 8))
    }
}

impl fmt::Debug for SessionTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SessionTokenDigest")
            .field(&self.safe_id())
            .finish()
    }
}

impl fmt::Display for SessionTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_id())
    }
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let count = count.min(bytes.len());
    let mut output = String::with_capacity(count * 2);
    for byte in &bytes[..count] {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

// ============================================================================
// Session Manager
// ============================================================================

/// Default maximum number of active sessions across all users.
pub const DEFAULT_MAX_GLOBAL_SESSIONS: u64 = 1_000;

/// Default maximum number of active sessions for one authenticated user.
pub const DEFAULT_MAX_SESSIONS_PER_USER: u64 = 10;

/// Session capacity limits enforced by the domain registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Maximum sessions across all users. `None` disables the global cap.
    pub max_global: Option<u64>,
    /// Maximum sessions for a single user. `None` disables the per-user cap.
    pub max_per_user: Option<u64>,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_global: Some(DEFAULT_MAX_GLOBAL_SESSIONS),
            max_per_user: Some(DEFAULT_MAX_SESSIONS_PER_USER),
        }
    }
}

#[derive(Clone, Debug)]
struct StoredSession {
    user: String,
    state: SessionState,
    created_at: u64,
    last_used_at: u64,
}

impl StoredSession {
    fn is_expired_at(&self, now: u64, idle_timeout_secs: u64) -> bool {
        match self.state {
            SessionState::Active => now.saturating_sub(self.last_used_at) >= idle_timeout_secs,
            SessionState::Expired => true,
        }
    }
}

/// In-memory domain session registry.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<SessionTokenDigest, StoredSession>>>,
    idle_timeout_secs: u64,
    limits: SessionLimits,
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_count = self.inner.lock().map(|guard| guard.len()).ok();
        formatter
            .debug_struct("SessionManager")
            .field("session_count", &session_count)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("limits", &self.limits)
            .finish()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout_secs: 300,
            limits: SessionLimits::default(),
        }
    }
}

impl SessionManager {
    /// Create a session manager with a custom idle timeout.
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self::with_limits(idle_timeout_secs, SessionLimits::default())
    }

    /// Create a session manager with custom idle timeout and capacity limits.
    pub fn with_limits(idle_timeout_secs: u64, limits: SessionLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout_secs,
            limits,
        }
    }

    /// Returns the configured idle timeout in seconds.
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    /// Returns the configured session capacity limits.
    pub fn limits(&self) -> SessionLimits {
        self.limits
    }

    /// Create a new active session.
    pub fn create(&self, user: impl Into<String>) -> Result<Session, GatewayError> {
        self.create_draining_expired(user)
            .map(|(session, _expired_tokens)| session)
    }

    /// Create a new active session and remove sessions that were already
    /// expired before capacity checks. Returned digests allow callers to clean
    /// up backend connections without retaining bearer tokens.
    pub fn create_draining_expired(
        &self,
        user: impl Into<String>,
    ) -> Result<(Session, Vec<SessionTokenDigest>), GatewayError> {
        let user = user.into();
        let token = format!("gvm_sess_{}", uuid::Uuid::new_v4().simple());
        let now = now_secs();
        let session = StoredSession {
            user: user.clone(),
            state: SessionState::Active,
            created_at: now,
            last_used_at: now,
        };
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        enforce_session_limits(&guard, &user, self.limits, now, self.idle_timeout_secs)?;
        let expired_tokens = expired_session_digests(&guard, now, self.idle_timeout_secs);
        for token_digest in &expired_tokens {
            guard.remove(token_digest);
        }
        guard.insert(SessionTokenDigest::from_token(&token), session);
        Ok((
            Session {
                token,
                user,
                state: SessionState::Active,
            },
            expired_tokens,
        ))
    }

    /// Look up a session by token.
    pub fn get(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        let guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let token_digest = SessionTokenDigest::from_token(token);
        Ok(guard.get(&token_digest).map(|stored| Session {
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
        let token_digest = SessionTokenDigest::from_token(token);
        let stored = guard
            .get(&token_digest)
            .ok_or_else(|| GatewayError::NotFound("session not found".to_string()))?;

        let (state, expires_in) = if stored.is_expired_at(now, self.idle_timeout_secs) {
            (SessionState::Expired, 0)
        } else {
            let elapsed = now.saturating_sub(stored.last_used_at);
            let remaining = (self.idle_timeout_secs - elapsed) as i64;
            (SessionState::Active, remaining)
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
        let token_digest = SessionTokenDigest::from_token(token);
        let stored = guard
            .get_mut(&token_digest)
            .ok_or_else(|| GatewayError::SessionInvalidated("missing session".to_string()))?;

        if stored.is_expired_at(now, self.idle_timeout_secs) {
            stored.state = SessionState::Expired;
            return Err(GatewayError::SessionExpired("session expired".to_string()));
        }

        stored.last_used_at = now;
        Ok(Session {
            token: token.to_string(),
            user: stored.user.clone(),
            state: SessionState::Active,
        })
    }

    /// Expire an existing session.
    pub fn expire(&self, token: &str) -> Result<(), GatewayError> {
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let token_digest = SessionTokenDigest::from_token(token);
        let stored = guard
            .get_mut(&token_digest)
            .ok_or_else(|| GatewayError::SessionInvalidated("missing session".to_string()))?;
        stored.state = SessionState::Expired;
        Ok(())
    }

    /// Remove all sessions that have exceeded the idle timeout or are already
    /// in a non-active state. Returns digest keys of the removed sessions so
    /// callers can perform backend cleanup without retaining bearer tokens.
    pub fn drain_expired(&self) -> Result<Vec<SessionTokenDigest>, GatewayError> {
        let now = now_secs();
        let mut guard = self.inner.lock().map_err(|_| {
            GatewayError::BackendUnavailable("session registry unavailable".to_string())
        })?;
        let expired_tokens = expired_session_digests(&guard, now, self.idle_timeout_secs);
        for token_digest in &expired_tokens {
            guard.remove(token_digest);
        }
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
            .remove(&SessionTokenDigest::from_token(token));
        Ok(removed.map(|stored| Session {
            token: token.to_string(),
            user: stored.user,
            state: stored.state,
        }))
    }
}

fn enforce_session_limits(
    sessions: &HashMap<SessionTokenDigest, StoredSession>,
    user: &str,
    limits: SessionLimits,
    now: u64,
    idle_timeout_secs: u64,
) -> Result<(), GatewayError> {
    if let Some(max_global) = limits.max_global {
        let active_sessions = sessions
            .values()
            .filter(|session| !session.is_expired_at(now, idle_timeout_secs))
            .count() as u64;
        if active_sessions >= max_global {
            return Err(GatewayError::TooManyRequests(
                "global session limit exceeded".to_string(),
            ));
        }
    }

    if let Some(max_per_user) = limits.max_per_user {
        let user_sessions = sessions
            .values()
            .filter(|session| {
                session.user == user && !session.is_expired_at(now, idle_timeout_secs)
            })
            .count() as u64;
        if user_sessions >= max_per_user {
            return Err(GatewayError::TooManyRequests(
                "per-user session limit exceeded".to_string(),
            ));
        }
    }

    Ok(())
}

fn expired_session_digests(
    sessions: &HashMap<SessionTokenDigest, StoredSession>,
    now: u64,
    idle_timeout_secs: u64,
) -> Vec<SessionTokenDigest> {
    sessions
        .iter()
        .filter_map(|(token_digest, stored)| {
            stored
                .is_expired_at(now, idle_timeout_secs)
                .then_some(*token_digest)
        })
        .collect()
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

        assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
    }

    #[test]
    fn session_manager_touch_fails_for_expired_session() {
        let manager = SessionManager::default();
        let session = manager.create("dave").unwrap();
        manager.expire(&session.token).unwrap();

        let result = manager.touch(&session.token);
        assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
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

        assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
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

    /// Session debug output redacts live bearer tokens because debug and panic
    /// output can be captured by logs.
    #[test]
    fn session_debug_redacts_token() {
        let manager = SessionManager::default();
        let session = manager.create("debug-user").unwrap();

        let debug = format!("{session:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&session.token));
    }

    /// SessionCreated debug output redacts the token returned to clients.
    #[test]
    fn session_created_debug_redacts_token() {
        let created = SessionCreated {
            token: "gvm_sess_debug_created_secret".to_string(),
            expires_in: 300,
            gmp_version: "22.7".to_string(),
        };

        let debug = format!("{created:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&created.token));
    }

    /// SessionInfo debug output redacts the inspected bearer token.
    #[test]
    fn session_info_debug_redacts_token() {
        let info = SessionInfo {
            token: "gvm_sess_debug_info_secret".to_string(),
            user: "debug-user".to_string(),
            state: SessionState::Active,
            created_at: 1,
            last_used_at: 1,
            expires_in: 300,
        };

        let debug = format!("{info:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&info.token));
    }

    /// SessionManager debug output exposes registry metadata only, never the
    /// raw token values used to access sessions.
    #[test]
    fn session_manager_debug_does_not_include_raw_token() {
        let manager = SessionManager::default();
        let session = manager.create("debug-user").unwrap();

        let debug = format!("{manager:?}");

        assert!(debug.contains("session_count"));
        assert!(!debug.contains(&session.token));
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
        assert_eq!(info.state, SessionState::Active);
        assert!(info.created_at > 0);
        assert!(info.last_used_at > 0);
        assert!(info.expires_in > 0);
    }

    /// get_info returns the typed expired state for a manually expired session.
    #[test]
    fn session_manager_get_info_expired() {
        let manager = SessionManager::default();
        let session = manager.create("bob").unwrap();
        manager.expire(&session.token).unwrap();
        let info = manager.get_info(&session.token).unwrap();

        assert_eq!(info.state, SessionState::Expired);
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

        assert!(matches!(result, Err(GatewayError::SessionExpired(_))));
    }

    /// idle_timeout_secs returns the configured value.
    #[test]
    fn session_manager_idle_timeout_secs() {
        let manager = SessionManager::new(600);
        assert_eq!(manager.idle_timeout_secs(), 600);
        assert_eq!(SessionManager::default().idle_timeout_secs(), 300);
    }

    /// Global session limits protect gvmd from process exhaustion by rejecting
    /// new sessions before another backend connection can be opened.
    #[test]
    fn session_manager_enforces_global_session_limit() {
        let manager = SessionManager::with_limits(
            300,
            SessionLimits {
                max_global: Some(1),
                max_per_user: None,
            },
        );

        manager.create("alice").unwrap();
        let result = manager.create("bob");

        assert!(matches!(result, Err(GatewayError::TooManyRequests(_))));
    }

    /// Per-user limits prevent one credential from consuming the whole
    /// session budget while still allowing other users to create sessions.
    #[test]
    fn session_manager_enforces_per_user_session_limit() {
        let manager = SessionManager::with_limits(
            300,
            SessionLimits {
                max_global: None,
                max_per_user: Some(1),
            },
        );

        manager.create("alice").unwrap();
        let result = manager.create("alice");
        let other_user = manager.create("bob");

        assert!(matches!(result, Err(GatewayError::TooManyRequests(_))));
        assert!(other_user.is_ok());
    }

    /// Explicit teardown releases capacity so a user can create a replacement
    /// session without waiting for idle-expiry cleanup.
    #[test]
    fn session_manager_remove_releases_session_limit_capacity() {
        let manager = SessionManager::with_limits(
            300,
            SessionLimits {
                max_global: Some(1),
                max_per_user: Some(1),
            },
        );
        let session = manager.create("alice").unwrap();

        manager.remove(&session.token).unwrap();
        let replacement = manager.create("alice");

        assert!(replacement.is_ok());
    }

    /// Idle-expired sessions do not consume global capacity during creation;
    /// replacement logins should not wait for the background reaper.
    #[test]
    fn session_manager_create_drains_idle_expired_global_capacity() {
        let manager = SessionManager::with_limits(
            0,
            SessionLimits {
                max_global: Some(1),
                max_per_user: None,
            },
        );
        let expired = manager.create("alice").unwrap();
        let expired_digest = SessionTokenDigest::from_token(&expired.token);

        let (replacement, drained) = manager.create_draining_expired("bob").unwrap();

        assert_eq!(drained, vec![expired_digest]);
        assert!(manager.get(&expired.token).unwrap().is_none());
        assert!(manager.get(&replacement.token).unwrap().is_some());
    }

    /// Idle-expired sessions from the same user do not consume per-user
    /// capacity during creation.
    #[test]
    fn session_manager_create_drains_idle_expired_per_user_capacity() {
        let manager = SessionManager::with_limits(
            0,
            SessionLimits {
                max_global: None,
                max_per_user: Some(1),
            },
        );
        let expired = manager.create("alice").unwrap();
        let expired_digest = SessionTokenDigest::from_token(&expired.token);

        let (replacement, drained) = manager.create_draining_expired("alice").unwrap();

        assert_eq!(drained, vec![expired_digest]);
        assert!(manager.get(&expired.token).unwrap().is_none());
        assert!(manager.get(&replacement.token).unwrap().is_some());
    }

    /// Explicitly expired sessions do not consume capacity during creation.
    #[test]
    fn session_manager_create_drains_explicitly_expired_capacity() {
        let manager = SessionManager::with_limits(
            300,
            SessionLimits {
                max_global: Some(1),
                max_per_user: Some(1),
            },
        );
        let expired = manager.create("alice").unwrap();
        let expired_digest = SessionTokenDigest::from_token(&expired.token);
        manager.expire(&expired.token).unwrap();

        let (replacement, drained) = manager.create_draining_expired("alice").unwrap();

        assert_eq!(drained, vec![expired_digest]);
        assert!(manager.get(&expired.token).unwrap().is_none());
        assert!(manager.get(&replacement.token).unwrap().is_some());
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

    /// drain_expired returns token digests for manually expired sessions and
    /// removes them without exposing raw bearer tokens.
    #[test]
    fn session_manager_drain_expired_manually_expired() {
        let manager = SessionManager::default();
        let s1 = manager.create("alice").unwrap();
        let s2 = manager.create("bob").unwrap();
        let s1_digest = SessionTokenDigest::from_token(&s1.token);
        manager.expire(&s1.token).unwrap();

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 1);
        assert!(drained.contains(&s1_digest));
        assert!(!format!("{drained:?}").contains(&s1.token));

        assert!(manager.get(&s1.token).unwrap().is_none());
        assert!(manager.get(&s2.token).unwrap().is_some());
    }

    /// drain_expired returns digests of idle-expired sessions (timeout == 0).
    #[test]
    fn session_manager_drain_expired_idle_timeout() {
        let manager = SessionManager::new(0);
        let s1 = manager.create("alice").unwrap();
        let s1_digest = SessionTokenDigest::from_token(&s1.token);

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 1);
        assert!(drained.contains(&s1_digest));

        assert!(manager.get(&s1.token).unwrap().is_none());
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

    /// drain_expired includes explicitly expired sessions.
    #[test]
    fn session_manager_drain_expired_includes_expired_sessions() {
        let manager = SessionManager::default();
        let session = manager.create("alice").unwrap();
        manager.expire(&session.token).unwrap();

        let drained = manager.drain_expired().unwrap();
        assert_eq!(drained.len(), 1);
    }
}
