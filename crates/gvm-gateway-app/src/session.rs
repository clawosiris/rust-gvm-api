// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Session lifecycle use cases and the background session reaper.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{field, info_span, Instrument};

use gvm_gateway_domain::{
    AuthPort, GatewayError, SessionCreated, SessionInfo, SessionManager, SessionTokenDigest,
};

use crate::{
    service::{emit_audit_event, emit_audit_event_with_session_id, safe_session_id},
    GatewayService,
};

// ============================================================================
// Session lifecycle use cases
// ============================================================================

impl GatewayService {
    /// Borrow the shared session manager.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.sessions)
    }

    /// Authenticates with the supplied credentials, creates a domain session,
    /// and establishes a backend connection bound to the new token.
    pub async fn create_session(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionCreated, GatewayError> {
        let span = info_span!(
            "session.create",
            otel_name = "session.create",
            gvmd_username = %username,
            session_id = field::Empty,
            audit_action = "create",
            audit_resource = "session"
        );

        async move {
            let (session, expired_session_digests) =
                self.sessions.create_draining_expired(username)?;
            disconnect_expired_sessions(
                Arc::clone(&self.auth),
                username,
                expired_session_digests,
                "session.create",
            )
            .await;
            tracing::Span::current().record(
                "session_id",
                field::display(safe_session_id(&session.token)),
            );

            let gmp_version = match self
                .auth
                .authenticate_session(&session.token, username, password)
                .await
            {
                Ok(version) => version,
                Err(err) => {
                    let _ = self.sessions.remove(&session.token);
                    emit_audit_event(
                        "session.create",
                        "failure",
                        username,
                        Some(&session.token),
                        None,
                        None,
                        Some(&err),
                    );
                    return Err(err);
                }
            };

            emit_audit_event(
                "session.create",
                "success",
                username,
                Some(&session.token),
                None,
                None,
                None,
            );

            Ok(SessionCreated {
                token: session.token,
                expires_in: self.sessions.idle_timeout_secs(),
                gmp_version,
            })
        }
        .instrument(span)
        .await
    }

    /// Returns detailed session information without extending the idle timer.
    pub fn get_session(&self, token: &str) -> Result<SessionInfo, GatewayError> {
        let _span = info_span!(
            "session.lookup",
            otel_name = "session.lookup",
            session_id = %safe_session_id(token),
            audit_action = "lookup",
            audit_resource = "session"
        )
        .entered();
        self.sessions.get_info(token)
    }

    /// Closes and destroys a session, disconnecting the backend connection.
    pub async fn delete_session(&self, token: &str) -> Result<(), GatewayError> {
        let span = info_span!(
            "session.teardown",
            otel_name = "session.teardown",
            session_id = %safe_session_id(token),
            audit_action = "delete",
            audit_resource = "session"
        );

        async move {
            let removed = self.sessions.remove(token)?;
            if removed.is_none() {
                let err = GatewayError::NotFound("session not found".to_string());
                emit_audit_event(
                    "session.delete",
                    "failure",
                    "unknown",
                    Some(token),
                    None,
                    None,
                    Some(&err),
                );
                return Err(err);
            }

            let removed = removed.expect("checked is_some");
            let session_digest = SessionTokenDigest::from_token(token);
            match self.cancel_jobs_for_session(&session_digest) {
                Ok(0) => {}
                Ok(count) => {
                    tracing::info!(count, "session.delete: cancelled session-bound jobs");
                }
                Err(err) => {
                    emit_audit_event(
                        "session.delete",
                        "job_cancel_failed",
                        &removed.user,
                        Some(token),
                        None,
                        None,
                        Some(&err),
                    );
                }
            }
            if let Err(err) = self.auth.disconnect_session(&session_digest).await {
                emit_audit_event(
                    "session.delete",
                    "backend_disconnect_failed",
                    &removed.user,
                    Some(token),
                    None,
                    None,
                    Some(&err),
                );
            }

            emit_audit_event(
                "session.delete",
                "success",
                &removed.user,
                Some(token),
                None,
                None,
                None,
            );

            Ok(())
        }
        .instrument(span)
        .await
    }
}

async fn disconnect_expired_sessions(
    auth: Arc<dyn AuthPort>,
    username: &str,
    session_digests: Vec<SessionTokenDigest>,
    event: &'static str,
) {
    for session_digest in &session_digests {
        let session_id = session_digest.safe_id();
        emit_audit_event_with_session_id(
            "session.expired",
            "cleanup",
            username,
            &session_id,
            None,
            Some("expire"),
            None,
        );
        if let Err(err) = auth.disconnect_session(session_digest).await {
            emit_audit_event_with_session_id(
                "session.disconnect",
                "failure",
                username,
                &session_id,
                None,
                Some("disconnect"),
                Some(&err),
            );
            tracing::warn!(session_id = %session_id, ?err, "{event}: disconnect_session failed");
        }
    }
}

// ============================================================================
// Session Reaper
// ============================================================================

/// Background task that periodically drains idle-expired sessions and
/// disconnects their backend connections.
///
/// This is a dedicated type that encapsulates the reaper lifecycle.
/// Construct it with [`SessionReaper::new`] and spawn it with
/// [`SessionReaper::spawn`].
pub struct SessionReaper {
    sessions: Arc<SessionManager>,
    auth: Arc<dyn AuthPort>,
}

impl SessionReaper {
    /// Create a new session reaper that will drain expired sessions from the
    /// given manager and disconnect them via the given auth port.
    pub fn new(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>) -> Self {
        Self { sessions, auth }
    }

    /// Spawn the reaper as a background Tokio task.
    ///
    /// The default sweep interval is half the idle timeout so that expired
    /// sessions are reaped within one full timeout period.  The returned
    /// [`JoinHandle`] can be aborted to stop the reaper (e.g. on server
    /// shutdown).
    pub fn spawn(&self) -> JoinHandle<()> {
        let interval = Duration::from_secs((self.sessions.idle_timeout_secs() / 2).max(1));
        self.spawn_with_interval(interval)
    }

    /// Like [`spawn`](Self::spawn) but with an explicit sweep interval
    /// (useful for testing).
    pub fn spawn_with_interval(&self, interval: Duration) -> JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let auth = Arc::clone(&self.auth);
        tokio::spawn(Self::run(sessions, auth, interval))
    }

    async fn run(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            Self::sweep_once(Arc::clone(&sessions), Arc::clone(&auth)).await;
        }
    }

    async fn sweep_once(sessions: Arc<SessionManager>, auth: Arc<dyn AuthPort>) {
        let session_digests = match sessions.drain_expired() {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(?err, "session reaper: drain_expired failed");
                return;
            }
        };
        let cleaned_count = session_digests.len();
        disconnect_expired_sessions(auth, "unknown", session_digests, "session reaper").await;
        if cleaned_count > 0 {
            tracing::info!(
                count = cleaned_count,
                "session reaper: cleaned up expired sessions"
            );
        }
    }

    #[cfg(test)]
    async fn sweep_once_for_test(&self) {
        Self::sweep_once(Arc::clone(&self.sessions), Arc::clone(&self.auth)).await;
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
        GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
                gmp_version: "22.7".to_string(),
            }),
            Arc::new(MockAlertPort),
            Arc::new(MockSchedulePort),
            Arc::new(MockCredentialPort),
            Arc::new(MockPortListPort),
            Arc::new(MockFeedPort),
            Arc::new(MockIdentityPort),
            Arc::new(MockTargetPort::default()),
            Arc::new(MockTaskPort),
            auth,
            Arc::new(MockReportPort),
            Arc::new(MockResultPort),
            Arc::new(MockScanConfigPort),
            Arc::new(MockScannerPort),
            Arc::new(MockSupportingResourcePort),
            sessions,
        )
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
        let service = GatewayService::new(
            Arc::new(MockSystemPort {
                ready: true,
                gmp_version: "22.7".to_string(),
            }),
            Arc::new(MockAlertPort),
            Arc::new(MockSchedulePort),
            Arc::new(MockCredentialPort),
            Arc::new(MockPortListPort),
            Arc::new(MockFeedPort),
            Arc::new(MockIdentityPort),
            Arc::new(MockTargetPort::default()),
            Arc::new(MockTaskPort),
            Arc::new(MockAuthPort {
                should_fail: true,
                ..Default::default()
            }),
            Arc::new(MockReportPort),
            Arc::new(MockResultPort),
            Arc::new(MockScanConfigPort),
            Arc::new(MockScannerPort),
            Arc::new(MockSupportingResourcePort),
            Arc::new(SessionManager::default()),
        );

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
        let service = create_test_service_with_auth_and_sessions(
            Arc::clone(&auth_arc),
            Arc::clone(&sessions),
        );
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
}
