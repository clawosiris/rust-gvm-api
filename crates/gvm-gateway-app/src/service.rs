// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Shared service shell and cross-resource execution helpers.

use std::sync::Arc;

use gvm_gateway_domain::{
    AlertPort, AuthPort, CredentialPort, FeedPort, GatewayError, IdentityPort, PortListPort,
    ReportPort, ResultPort, ScanConfigPort, ScannerPort, SchedulePort, SessionManager,
    SupportingResourcePort, SystemPort, TargetPort, TaskPort,
};
use tracing::{field, info_span, Instrument};

pub(crate) const AUDIT_TARGET: &str = "gvm_gateway_app::audit";

/// Application services exposed to adapters.
///
/// Ports are held as trait objects so that adding a new resource does not
/// require touching unrelated handler signatures.
pub struct GatewayService {
    pub(crate) system: Arc<dyn SystemPort>,
    pub(crate) alerts: Arc<dyn AlertPort>,
    pub(crate) schedules: Arc<dyn SchedulePort>,
    pub(crate) credentials: Arc<dyn CredentialPort>,
    pub(crate) port_lists: Arc<dyn PortListPort>,
    pub(crate) feeds: Arc<dyn FeedPort>,
    pub(crate) identity: Arc<dyn IdentityPort>,
    pub(crate) targets: Arc<dyn TargetPort>,
    pub(crate) tasks: Arc<dyn TaskPort>,
    pub(crate) auth: Arc<dyn AuthPort>,
    pub(crate) reports: Arc<dyn ReportPort>,
    pub(crate) results: Arc<dyn ResultPort>,
    pub(crate) scan_configs: Arc<dyn ScanConfigPort>,
    pub(crate) scanners: Arc<dyn ScannerPort>,
    pub(crate) supporting_resources: Arc<dyn SupportingResourcePort>,
    pub(crate) sessions: Arc<SessionManager>,
}

impl GatewayService {
    /// Creates a new service backed by the provided ports and session manager.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system: Arc<dyn SystemPort>,
        alerts: Arc<dyn AlertPort>,
        schedules: Arc<dyn SchedulePort>,
        credentials: Arc<dyn CredentialPort>,
        port_lists: Arc<dyn PortListPort>,
        feeds: Arc<dyn FeedPort>,
        identity: Arc<dyn IdentityPort>,
        targets: Arc<dyn TargetPort>,
        tasks: Arc<dyn TaskPort>,
        auth: Arc<dyn AuthPort>,
        reports: Arc<dyn ReportPort>,
        results: Arc<dyn ResultPort>,
        scan_configs: Arc<dyn ScanConfigPort>,
        scanners: Arc<dyn ScannerPort>,
        supporting_resources: Arc<dyn SupportingResourcePort>,
        sessions: Arc<SessionManager>,
    ) -> Self {
        Self {
            system,
            alerts,
            schedules,
            credentials,
            port_lists,
            feeds,
            identity,
            targets,
            tasks,
            auth,
            reports,
            results,
            scan_configs,
            scanners,
            supporting_resources,
            sessions,
        }
    }

    pub(crate) fn get_username_for_audit(&self, session_token: &str) -> Option<String> {
        self.sessions
            .get(session_token)
            .ok()
            .flatten()
            .map(|session| session.user)
    }

    pub(crate) fn touch_session_with_audit(
        &self,
        session_token: &str,
    ) -> Result<gvm_gateway_domain::Session, GatewayError> {
        match self.sessions.touch(session_token) {
            Ok(session) => Ok(session),
            Err(err) => {
                let reason = match &err {
                    GatewayError::SessionExpired(_) => "session.expired",
                    GatewayError::SessionInvalidated(_) => "session.invalidated",
                    _ => "session.lookup_failed",
                };
                emit_audit_event(
                    reason,
                    "failure",
                    self.get_username_for_audit(session_token)
                        .as_deref()
                        .unwrap_or("unknown"),
                    Some(session_token),
                    None,
                    None,
                    Some(&err),
                );
                Err(err)
            }
        }
    }

    pub(crate) async fn execute_with_resource<F, Fut, T>(
        &self,
        span_name: &'static str,
        session_token: &str,
        action: &'static str,
        resource: &'static str,
        resource_id: Option<&str>,
        operation: F,
    ) -> Result<T, GatewayError>
    where
        F: FnOnce(gvm_gateway_domain::Session) -> Fut,
        Fut: std::future::Future<Output = Result<T, GatewayError>>,
    {
        let user = self.get_username_for_audit(session_token);
        let span = execution_span(span_name, session_token, user.as_deref(), action, resource);
        span.record("resource_id", resource_id.unwrap_or(""));

        async move {
            emit_audit_event(
                "command.execution",
                "start",
                user.as_deref().unwrap_or("unknown"),
                Some(session_token),
                Some(resource),
                Some(action),
                None,
            );

            let session = self.touch_session_with_audit(session_token)?;
            let username = session.user.clone();

            match operation(session).await {
                Ok(result) => {
                    emit_audit_event(
                        "command.execution",
                        "success",
                        &username,
                        Some(session_token),
                        Some(resource),
                        Some(action),
                        None,
                    );
                    Ok(result)
                }
                Err(err) => {
                    emit_audit_event(
                        "command.execution",
                        "failure",
                        &username,
                        Some(session_token),
                        Some(resource),
                        Some(action),
                        Some(&err),
                    );
                    Err(err)
                }
            }
        }
        .instrument(span)
        .await
    }
}

pub(crate) fn execution_span(
    name: &'static str,
    session_token: &str,
    username: Option<&str>,
    action: &'static str,
    resource: &'static str,
) -> tracing::Span {
    info_span!(
        "command.execution",
        otel_name = name,
        gvmd_username = %username.unwrap_or("unknown"),
        session_id = %safe_session_id(session_token),
        audit_action = action,
        audit_resource = resource,
        resource_id = field::Empty
    )
}

pub(crate) fn safe_session_id(token: &str) -> String {
    let suffix: String = token
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("session:{suffix}")
}

fn error_category(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::BackendUnavailable(_) => "backend_unavailable",
        GatewayError::NotFound(_) => "not_found",
        GatewayError::InvalidInput(_) => "invalid_input",
        GatewayError::Unauthorized(_) => "unauthorized",
        GatewayError::SessionExpired(_) => "session_expired",
        GatewayError::SessionInvalidated(_) => "session_invalidated",
        GatewayError::Forbidden(_) => "forbidden",
        GatewayError::Conflict(_) => "conflict",
        GatewayError::TooManyRequests(_) => "too_many_requests",
        GatewayError::Internal(_) => "internal_server_error",
        GatewayError::GatewayTimeout(_) => "gateway_timeout",
    }
}

pub(crate) fn emit_audit_event(
    event: &str,
    outcome: &str,
    username: &str,
    session_token: Option<&str>,
    resource: Option<&str>,
    action: Option<&str>,
    error: Option<&GatewayError>,
) {
    tracing::info!(
        target: AUDIT_TARGET,
        audit_event = event,
        audit_outcome = outcome,
        gvmd_username = username,
        session_id = session_token
            .map(safe_session_id)
            .unwrap_or_else(|| "session:unknown".to_string()),
        resource = resource.unwrap_or("session"),
        action = action.unwrap_or("none"),
        error_category = error.map(error_category).unwrap_or("none"),
        error = error.map(|err| format!("{err:?}")).unwrap_or_default(),
        "audit_event"
    );
}

impl Clone for GatewayService {
    fn clone(&self) -> Self {
        Self {
            system: Arc::clone(&self.system),
            alerts: Arc::clone(&self.alerts),
            schedules: Arc::clone(&self.schedules),
            credentials: Arc::clone(&self.credentials),
            port_lists: Arc::clone(&self.port_lists),
            feeds: Arc::clone(&self.feeds),
            identity: Arc::clone(&self.identity),
            targets: Arc::clone(&self.targets),
            tasks: Arc::clone(&self.tasks),
            auth: Arc::clone(&self.auth),
            reports: Arc::clone(&self.reports),
            results: Arc::clone(&self.results),
            scan_configs: Arc::clone(&self.scan_configs),
            scanners: Arc::clone(&self.scanners),
            supporting_resources: Arc::clone(&self.supporting_resources),
            sessions: Arc::clone(&self.sessions),
        }
    }
}
