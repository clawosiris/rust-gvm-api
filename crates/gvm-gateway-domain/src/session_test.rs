// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

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

/// Session holds protect active backend work from idle cleanup.
#[test]
fn session_manager_hold_prevents_idle_drain() {
    let manager = SessionManager::new(1);
    let session = manager.create("alice").unwrap();
    let _hold = manager.hold(&session.token).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let drained = manager.drain_expired().unwrap();

    assert!(drained.is_empty());
    assert!(manager.get(&session.token).unwrap().is_some());
}

/// get_info reports held sessions as active with a positive lifetime while
/// backend work has suspended idle expiry.
#[test]
fn session_manager_get_info_held_session_reports_positive_expiry() {
    let manager = SessionManager::new(1);
    let session = manager.create("alice").unwrap();
    let _hold = manager.hold(&session.token).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let info = manager.get_info(&session.token).unwrap();

    assert_eq!(info.state, SessionState::Active);
    assert!(info.expires_in > 0);
}

/// Dropping the last hold restores the normal idle expiry behavior.
#[test]
fn session_manager_drain_expires_after_hold_drop() {
    let manager = SessionManager::new(1);
    let session = manager.create("alice").unwrap();
    let hold = manager.hold(&session.token).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    drop(hold);

    let drained = manager.drain_expired().unwrap();

    assert_eq!(
        drained,
        vec![SessionTokenDigest::from_token(&session.token)]
    );
    assert!(manager.get(&session.token).unwrap().is_none());
}

/// Explicit session removal wins over a hold and leaves guard drop harmless.
#[test]
fn session_manager_remove_while_held_invalidates_session() {
    let manager = SessionManager::default();
    let session = manager.create("alice").unwrap();
    let hold = manager.hold(&session.token).unwrap();

    let removed = manager.remove(&session.token).unwrap();
    drop(hold);

    assert!(removed.is_some());
    assert!(manager.get(&session.token).unwrap().is_none());
}
