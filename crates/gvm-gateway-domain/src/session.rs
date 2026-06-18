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
    hold_count: u64,
}

impl StoredSession {
    fn is_expired_at(&self, now: u64, idle_timeout_secs: u64) -> bool {
        match self.state {
            SessionState::Active if self.hold_count > 0 => false,
            SessionState::Active => now.saturating_sub(self.last_used_at) >= idle_timeout_secs,
            SessionState::Expired => true,
        }
    }
}

/// RAII guard that keeps a session active while backend work depends on it.
pub struct SessionHold {
    inner: Arc<Mutex<HashMap<SessionTokenDigest, StoredSession>>>,
    token_digest: SessionTokenDigest,
}

impl Drop for SessionHold {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(session) = guard.get_mut(&self.token_digest) {
                session.hold_count = session.hold_count.saturating_sub(1);
            }
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
            hold_count: 0,
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
        } else if stored.hold_count > 0 {
            (SessionState::Active, self.idle_timeout_secs.max(1) as i64)
        } else {
            let elapsed = now.saturating_sub(stored.last_used_at);
            let remaining = self.idle_timeout_secs.saturating_sub(elapsed) as i64;
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

    /// Hold an active session so idle cleanup does not remove it while
    /// asynchronous backend work is still using the associated connection.
    pub fn hold(&self, token: &str) -> Result<SessionHold, GatewayError> {
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

        stored.hold_count = stored.hold_count.saturating_add(1);
        stored.last_used_at = now;
        Ok(SessionHold {
            inner: Arc::clone(&self.inner),
            token_digest,
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
#[path = "session_test.rs"]
mod session_test;
