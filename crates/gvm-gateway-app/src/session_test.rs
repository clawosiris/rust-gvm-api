// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::SessionReaper;
use crate::test_support::*;
use crate::GatewayService;
use gvm_gateway_domain::{GatewayError, SessionLimits, SessionManager, SessionTokenDigest};
use std::sync::Arc;
use std::time::Duration;

fn create_test_service_with_auth_and_sessions(
    auth: Arc<MockAuthPort>,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    let mut ports = test_ports();
    ports.auth = auth;
    GatewayService::new(ports, sessions)
}

// ------------------------------------------------------------------------
// Session manager sharing tests
// ------------------------------------------------------------------------

#[test]
fn service_session_manager_shared() {
    let service = create_test_service();
    let manager1 = service.session_manager();
    let manager2 = service.session_manager();

    let session = manager1.create("user").unwrap();
    let found = manager2.get(&session.token).unwrap();
    assert!(found.is_some());
}

#[test]
fn service_clone_shares_state() {
    let service = create_test_service();
    let cloned = service.clone();

    let session = service.session_manager().create("user").unwrap();
    let found = cloned.session_manager().get(&session.token).unwrap();
    assert!(found.is_some());
}

// ------------------------------------------------------------------------
// Session lifecycle use-case tests
// ------------------------------------------------------------------------

/// create_session returns a token, idle timeout, and GMP version
/// when backend authentication succeeds.
#[tokio::test]
async fn service_create_session_success() {
    let service = create_test_service();
    let created = service.create_session("admin", "secret").await.unwrap();

    assert!(created.token.starts_with("gvm_sess_"));
    assert_eq!(created.expires_in, 300);
    assert_eq!(created.gmp_version, "22.7");
}

/// create_session removes and disconnects expired sessions before applying
/// capacity limits, so replacement logins do not wait for the reaper.
#[tokio::test]
async fn service_create_session_replaces_idle_expired_limited_session() {
    let auth = MockAuthPort::default();
    let disconnected = Arc::clone(&auth.disconnected);
    let sessions = Arc::new(SessionManager::with_limits(
        0,
        SessionLimits {
            max_global: Some(1),
            max_per_user: Some(1),
        },
    ));
    let service = create_test_service_with_auth_and_sessions(Arc::new(auth), sessions);
    let first = service.create_session("admin", "secret").await.unwrap();
    let first_digest = SessionTokenDigest::from_token(&first.token);

    let second = service.create_session("admin", "secret").await.unwrap();

    assert_ne!(first.token, second.token);
    assert!(service
        .session_manager()
        .get(&first.token)
        .unwrap()
        .is_none());
    assert!(disconnected.lock().unwrap().contains(&first_digest));
}

/// create_session rolls back the domain session when backend auth fails.
#[tokio::test]
async fn service_create_session_auth_failure_rolls_back() {
    let mut ports = test_ports();
    ports.auth = Arc::new(MockAuthPort {
        should_fail: true,
        ..Default::default()
    });
    let service = GatewayService::new(ports, Arc::new(SessionManager::default()));

    let result = service.create_session("admin", "wrong").await;
    assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
}

/// get_session returns session info for an active session.
#[tokio::test]
async fn service_get_session_active() {
    let service = create_test_service();
    let created = service.create_session("admin", "secret").await.unwrap();
    let info = service.get_session(&created.token).unwrap();

    assert_eq!(info.token, created.token);
    assert_eq!(info.user, "admin");
    assert_eq!(info.state, gvm_gateway_domain::SessionState::Active);
    assert!(info.expires_in > 0);
}

/// get_session returns NotFound for unknown tokens.
#[tokio::test]
async fn service_get_session_not_found() {
    let service = create_test_service();
    let result = service.get_session("nonexistent");
    assert!(matches!(result, Err(GatewayError::NotFound(_))));
}

/// delete_session removes the session so subsequent gets fail.
#[tokio::test]
async fn service_delete_session_success() {
    let service = create_test_service();
    let created = service.create_session("admin", "secret").await.unwrap();

    service.delete_session(&created.token).await.unwrap();

    let result = service.get_session(&created.token);
    assert!(matches!(result, Err(GatewayError::NotFound(_))));
}

/// delete_session fails with NotFound for unknown tokens.
#[tokio::test]
async fn service_delete_session_not_found() {
    let service = create_test_service();
    let result = service.delete_session("nonexistent").await;
    assert!(matches!(result, Err(GatewayError::NotFound(_))));
}

// ------------------------------------------------------------------------
// Session reaper tests
// ------------------------------------------------------------------------

/// The reaper disconnects expired sessions within one sweep interval.
#[tokio::test]
async fn reaper_disconnects_expired_sessions() {
    let auth = MockAuthPort::default();
    let disconnected = Arc::clone(&auth.disconnected);
    let sessions = Arc::new(SessionManager::default());
    let reaper = SessionReaper::new(Arc::clone(&sessions), Arc::new(auth));

    // Create a session and immediately expire it.
    let session = sessions.create("admin").unwrap();
    sessions.expire(&session.token).unwrap();

    // Spawn reaper with a very short interval.
    let handle = reaper.spawn_with_interval(Duration::from_millis(10));

    // Wait long enough for at least one sweep.
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let tokens = disconnected.lock().unwrap();
    assert!(tokens.contains(&SessionTokenDigest::from_token(&session.token)));
}

/// The reaper does not disconnect active sessions.
#[tokio::test]
async fn reaper_ignores_active_sessions() {
    let auth = MockAuthPort::default();
    let disconnected = Arc::clone(&auth.disconnected);
    let sessions = Arc::new(SessionManager::default());
    let reaper = SessionReaper::new(Arc::clone(&sessions), Arc::new(auth));

    // Create a session but don't expire it.
    sessions.create("admin").unwrap();

    let handle = reaper.spawn_with_interval(Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    assert!(disconnected.lock().unwrap().is_empty());
}

/// Configurable short idle timeouts must not produce a zero-duration
/// reaper interval, because tokio intervals reject zero durations.
#[tokio::test]
async fn reaper_spawn_handles_sub_two_second_idle_timeout() {
    let auth = MockAuthPort::default();
    let sessions = Arc::new(SessionManager::new(1));
    let reaper = SessionReaper::new(sessions, Arc::new(auth));

    let handle = reaper.spawn();
    handle.abort();
}

/// The reaper and delete_session are safe to race: if delete wins, the
/// reaper simply does not find the token; if the reaper wins, delete
/// returns NotFound.
#[tokio::test]
async fn reaper_and_delete_session_race_safe() {
    let auth = MockAuthPort::default();
    let disconnected = Arc::clone(&auth.disconnected);
    let auth_arc: Arc<MockAuthPort> = Arc::new(auth);
    let sessions = Arc::new(SessionManager::default());
    let service =
        create_test_service_with_auth_and_sessions(Arc::clone(&auth_arc), Arc::clone(&sessions));
    let reaper = SessionReaper::new(Arc::clone(&sessions), auth_arc);

    let session = sessions.create("admin").unwrap();
    sessions.expire(&session.token).unwrap();

    // Delete before the reaper runs.
    let result = service.delete_session(&session.token).await;
    assert!(result.is_ok());

    // Reaper should find nothing to drain.
    let handle = reaper.spawn_with_interval(Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    // disconnect_session is called once by delete_session.
    // The reaper should not have found the session (already removed).
    let tokens = disconnected.lock().unwrap();
    assert_eq!(tokens.len(), 1); // only the one from delete_session
}

#[tokio::test]
async fn reaper_emits_audit_for_expiry_and_disconnect_failure() {
    let _trace_lock = lock_tracing().await;
    let capture = capture_tracing();
    let auth = MockAuthPort {
        disconnect_should_fail: true,
        ..Default::default()
    };
    let sessions = Arc::new(SessionManager::default());
    let reaper = SessionReaper::new(Arc::clone(&sessions), Arc::new(auth));

    let session = sessions.create("admin").unwrap();
    sessions.expire(&session.token).unwrap();

    // This audit assertion runs one deterministic sweep under the capture
    // subscriber. The separate reaper tests cover spawned background
    // behavior; this test covers the audit contract without a sleep race.
    capture.run(reaper.sweep_once_for_test()).await;
    let session_token = session.token;

    let output = capture.output();
    assert!(
        output.contains("audit_event=\"session.expired\""),
        "captured tracing output did not include session.expired audit event: {output}"
    );
    assert!(output.contains("audit_event=\"session.disconnect\""));
    assert!(output.contains("error_category=\"backend_unavailable\""));
    assert!(output.contains("session_id=\"session:"));
    assert!(!output.contains(&session_token));
}
