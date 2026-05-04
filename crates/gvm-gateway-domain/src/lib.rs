// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Domain types and ports for the GVM gateway.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Domain Value Objects
// ============================================================================

/// Minimal reference to a related resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    /// Resource identifier.
    pub id: String,
    /// Optional resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Domain target representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Target {
    /// Target identifier.
    pub id: String,
    /// Target name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    #[serde(
        rename = "excludeHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude_hosts: Vec<String>,
    /// Optional alive-test strategy.
    #[serde(rename = "aliveTest", skip_serializing_if = "Option::is_none")]
    pub alive_test: Option<String>,
    /// Optional port list reference.
    #[serde(rename = "portList", skip_serializing_if = "Option::is_none")]
    pub port_list: Option<ResourceRef>,
    /// Reverse lookup only.
    #[serde(rename = "reverseLookupOnly")]
    pub reverse_lookup_only: bool,
    /// Reverse lookup unify.
    #[serde(rename = "reverseLookupUnify")]
    pub reverse_lookup_unify: bool,
    /// Optional SSH credential reference.
    #[serde(rename = "sshCredential", skip_serializing_if = "Option::is_none")]
    pub ssh_credential: Option<ResourceRef>,
    /// Optional SMB credential reference.
    #[serde(rename = "smbCredential", skip_serializing_if = "Option::is_none")]
    pub smb_credential: Option<ResourceRef>,
    /// Optional ESXi credential reference.
    #[serde(rename = "esxiCredential", skip_serializing_if = "Option::is_none")]
    pub esxi_credential: Option<ResourceRef>,
    /// Optional SNMP credential reference.
    #[serde(rename = "snmpCredential", skip_serializing_if = "Option::is_none")]
    pub snmp_credential: Option<ResourceRef>,
    /// Whether the target is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
    /// Whether the target is writable.
    pub writable: bool,
}

/// Pagination metadata for list responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pagination {
    /// Current page.
    pub page: u32,
    /// Page size.
    #[serde(rename = "perPage")]
    pub per_page: u32,
    /// Total matching resources.
    pub total: u32,
    /// Total number of pages.
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}

/// Paginated target list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetPage {
    /// Page items.
    pub data: Vec<Target>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Target list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Target create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTargetInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Host entries.
    pub hosts: Vec<String>,
    /// Excluded host entries.
    pub exclude_hosts: Vec<String>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
    /// Optional reverse lookup only.
    pub reverse_lookup_only: Option<bool>,
    /// Optional reverse lookup unify.
    pub reverse_lookup_unify: Option<bool>,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<String>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<String>,
    /// Optional ESXi credential identifier.
    pub esxi_credential_id: Option<String>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<String>,
}

/// Target update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyTargetInput {
    /// Optional name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional hosts.
    pub hosts: Option<Vec<String>>,
    /// Optional excluded hosts.
    pub exclude_hosts: Option<Vec<String>>,
    /// Optional alive test.
    pub alive_test: Option<String>,
    /// Optional port list identifier.
    pub port_list_id: Option<String>,
}

// ============================================================================
// Report Domain Types
// ============================================================================

/// Domain report representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Report {
    /// Report identifier.
    pub id: String,
    /// Associated task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Scan start timestamp.
    #[serde(rename = "scanStart", skip_serializing_if = "Option::is_none")]
    pub scan_start: Option<String>,
    /// Scan end timestamp.
    #[serde(rename = "scanEnd", skip_serializing_if = "Option::is_none")]
    pub scan_end: Option<String>,
    /// Highest severity found in the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Result counts by severity category.
    #[serde(rename = "resultCount", skip_serializing_if = "Option::is_none")]
    pub result_count: Option<ResultCount>,
    /// Embedded results (when fetching a single report).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ScanResult>,
}

/// Result counts by severity category for a report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResultCount {
    /// Total number of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    /// Number of high-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u32>,
    /// Number of medium-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,
    /// Number of low-severity results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low: Option<u32>,
    /// Number of log-level results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<u32>,
    /// Number of false-positive results.
    #[serde(rename = "falsePositive", skip_serializing_if = "Option::is_none")]
    pub false_positive: Option<u32>,
}

/// Paginated report list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReportPage {
    /// Page items.
    pub data: Vec<Report>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Report list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Options for fetching a single report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GetReportOpts {
    /// Whether to ignore pagination and return all results.
    pub ignore_pagination: bool,
}

// ============================================================================
// Result Domain Types
// ============================================================================

/// Domain scan result representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScanResult {
    /// Result identifier.
    pub id: String,
    /// NVT name.
    pub name: String,
    /// Target host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Target port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Severity score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<f64>,
    /// Threat level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    /// NVT reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvt: Option<NvtRef>,
    /// Result description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Associated task reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<ResourceRef>,
    /// Associated report reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ResourceRef>,
}

/// NVT (Network Vulnerability Test) reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NvtRef {
    /// NVT OID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    /// NVT name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// NVT family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// CVSS base score.
    #[serde(rename = "cvssBase", skip_serializing_if = "Option::is_none")]
    pub cvss_base: Option<f64>,
    /// CVE identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cves: Vec<String>,
    /// NVT tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

/// Paginated result list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResultPage {
    /// Page items.
    pub data: Vec<ScanResult>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Result list query options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResultQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

// ============================================================================
// Conversion Utilities
// ============================================================================

/// Convert a typed rust-gvm report into the domain representation.
pub fn report_from_gmp(report: gvm_gmp::responses::Report) -> Report {
    let severity = report
        .severity
        .as_ref()
        .and_then(|s| s.full.as_deref())
        .and_then(|v| v.parse::<f64>().ok());

    Report {
        id: report.meta.id.to_string(),
        task: report.task.map(|t| ResourceRef {
            id: t.id.to_string(),
            name: Some(t.name),
        }),
        scan_start: report.scan_start,
        scan_end: report.scan_end,
        severity,
        result_count: report.result_count.map(|rc| ResultCount {
            total: rc.full,
            high: None,
            medium: None,
            low: None,
            log: None,
            false_positive: None,
        }),
        results: vec![],
    }
}

/// Convert a typed rust-gvm scan result into the domain representation.
pub fn result_from_gmp(result: gvm_gmp::responses::ScanResult) -> ScanResult {
    let severity = result
        .severity
        .as_deref()
        .and_then(|v| v.parse::<f64>().ok());

    let nvt = result.nvt.map(|n| NvtRef {
        oid: Some(n.oid),
        name: n.name,
        family: n.family,
        cvss_base: n.cvss_base.as_deref().and_then(|v| v.parse::<f64>().ok()),
        cves: vec![],
        tags: None,
    });

    ScanResult {
        id: result.meta.id.to_string(),
        name: result.meta.name,
        host: result.host,
        port: result.port,
        severity,
        threat: result.threat,
        nvt,
        description: result.description,
        task: None,
        report: None,
    }
}

/// Convert a typed rust-gvm target into the domain representation.
pub fn target_from_gmp(target: gvm_gmp::responses::Target) -> Target {
    Target {
        id: target.meta.id.to_string(),
        name: target.meta.name,
        comment: target.meta.comment,
        hosts: target.hosts,
        exclude_hosts: target.exclude_hosts,
        alive_test: target.alive_tests,
        port_list: target.port_list.map(|resource| ResourceRef {
            id: resource.id.to_string(),
            name: Some(resource.name),
        }),
        reverse_lookup_only: target.reverse_lookup_only,
        reverse_lookup_unify: target.reverse_lookup_unify,
        ssh_credential: None,
        smb_credential: None,
        esxi_credential: None,
        snmp_credential: None,
        in_use: target.meta.in_use,
        writable: target.meta.writable,
    }
}

// ============================================================================
// Health & Readiness
// ============================================================================

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
        let token = format!("gvm_sess_{}", Uuid::new_v4().simple());
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

/// Port for session authentication with the backend.
#[async_trait]
pub trait AuthPort: Send + Sync + 'static {
    /// Authenticate and establish a backend connection for the session.
    async fn authenticate_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError>;

    /// Disconnect and clean up the backend connection for a session.
    async fn disconnect_session(&self, session_token: &str) -> Result<(), GatewayError>;
}

/// Port for report operations.
#[async_trait]
pub trait ReportPort: Send + Sync + 'static {
    /// List reports for the session.
    async fn list_reports(
        &self,
        session_token: &str,
        query: &ReportQuery,
    ) -> Result<ReportPage, GatewayError>;

    /// Fetch a report by identifier, optionally with embedded results.
    async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: &GetReportOpts,
    ) -> Result<Report, GatewayError>;

    /// Delete a report by identifier.
    async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// List results for a specific report.
    async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;
}

/// Port for result operations.
#[async_trait]
pub trait ResultPort: Send + Sync + 'static {
    /// List results for the session.
    async fn list_results(
        &self,
        session_token: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError>;

    /// Fetch a result by identifier.
    async fn get_result(&self, session_token: &str, id: &str) -> Result<ScanResult, GatewayError>;
}

/// Port for target CRUD operations.
#[async_trait]
pub trait TargetPort: Send + Sync + 'static {
    /// List targets for the session.
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError>;

    /// Create a new target.
    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a target by identifier.
    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError>;

    /// Modify a target by identifier.
    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError>;

    /// Delete a target by identifier.
    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;
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
    // GatewayError tests
    // ------------------------------------------------------------------------

    #[test]
    fn gateway_error_variants_distinguishable() {
        let backend = GatewayError::BackendUnavailable("down".to_string());
        let not_found = GatewayError::NotFound("missing".to_string());
        let invalid = GatewayError::InvalidInput("bad".to_string());
        let unauth = GatewayError::Unauthorized("denied".to_string());

        assert!(matches!(backend, GatewayError::BackendUnavailable(_)));
        assert!(matches!(not_found, GatewayError::NotFound(_)));
        assert!(matches!(invalid, GatewayError::InvalidInput(_)));
        assert!(matches!(unauth, GatewayError::Unauthorized(_)));
    }

    // ------------------------------------------------------------------------
    // Domain type tests
    // ------------------------------------------------------------------------

    #[test]
    fn health_status_serializes() {
        let status = HealthStatus { status: "ok" };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn readiness_status_omits_none_reason() {
        let status = ReadinessStatus {
            status: "ready",
            reason: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("reason"));
    }

    #[test]
    fn readiness_status_includes_reason() {
        let status = ReadinessStatus {
            status: "notReady",
            reason: Some("gvmd offline".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"reason\":\"gvmd offline\""));
    }

    #[test]
    fn version_info_camel_case_fields() {
        let info = VersionInfo {
            api_version: "1.0.0".to_string(),
            gmp_version: "22.7".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"gmpVersion\""));
    }

    #[test]
    fn pagination_serializes_camel_case() {
        let pagination = Pagination {
            page: 1,
            per_page: 25,
            total: 100,
            total_pages: 4,
        };
        let json = serde_json::to_string(&pagination).unwrap();
        assert!(json.contains("\"perPage\""));
        assert!(json.contains("\"totalPages\""));
    }

    #[test]
    fn target_query_default() {
        let query = TargetQuery::default();
        assert_eq!(query.page, 0);
        assert_eq!(query.per_page, 0);
        assert!(query.filter_string.is_none());
        assert!(query.filter_id.is_none());
    }

    #[test]
    fn modify_target_input_default() {
        let input = ModifyTargetInput::default();
        assert!(input.name.is_none());
        assert!(input.comment.is_none());
        assert!(input.hosts.is_none());
    }

    #[test]
    fn target_serializes_exclude_hosts_only_when_nonempty() {
        let target_with_excludes = Target {
            id: "123".to_string(),
            name: "test".to_string(),
            comment: None,
            hosts: vec!["10.0.0.1".to_string()],
            exclude_hosts: vec!["10.0.0.2".to_string()],
            alive_test: None,
            port_list: None,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            ssh_credential: None,
            smb_credential: None,
            esxi_credential: None,
            snmp_credential: None,
            in_use: false,
            writable: true,
        };
        let json_with = serde_json::to_string(&target_with_excludes).unwrap();
        assert!(json_with.contains("\"excludeHosts\""));

        let target_no_excludes = Target {
            exclude_hosts: vec![],
            ..target_with_excludes
        };
        let json_without = serde_json::to_string(&target_no_excludes).unwrap();
        assert!(!json_without.contains("excludeHosts"));
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
        // Use a very short timeout so we can test expiry immediately.
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

    #[test]
    fn resource_ref_name_optional() {
        let with_name = ResourceRef {
            id: "abc".to_string(),
            name: Some("Port List".to_string()),
        };
        let json = serde_json::to_string(&with_name).unwrap();
        assert!(json.contains("\"name\""));

        let without_name = ResourceRef {
            id: "abc".to_string(),
            name: None,
        };
        let json = serde_json::to_string(&without_name).unwrap();
        assert!(!json.contains("\"name\""));
    }

    // ------------------------------------------------------------------------
    // Report domain type tests
    // ------------------------------------------------------------------------

    /// Report serializes camelCase fields and omits None/empty values.
    #[test]
    fn report_serializes_camel_case() {
        let report = Report {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            task: Some(ResourceRef {
                id: "task-1".to_string(),
                name: Some("Scan".to_string()),
            }),
            scan_start: Some("2026-01-01T00:00:00Z".to_string()),
            scan_end: None,
            severity: Some(7.5),
            result_count: Some(ResultCount {
                total: Some(10),
                high: Some(2),
                medium: Some(3),
                low: Some(1),
                log: Some(4),
                false_positive: None,
            }),
            results: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"scanStart\""));
        assert!(!json.contains("\"scanEnd\""));
        assert!(json.contains("\"resultCount\""));
        assert!(!json.contains("\"falsePositive\""));
        assert!(!json.contains("\"results\""));
    }

    /// ResultCount omits None fields.
    #[test]
    fn result_count_omits_none_fields() {
        let rc = ResultCount {
            total: Some(5),
            high: None,
            medium: None,
            low: None,
            log: None,
            false_positive: None,
        };
        let json = serde_json::to_string(&rc).unwrap();
        assert!(json.contains("\"total\""));
        assert!(!json.contains("\"high\""));
    }

    /// ReportQuery defaults to zero page/per_page.
    #[test]
    fn report_query_default() {
        let query = ReportQuery::default();
        assert_eq!(query.page, 0);
        assert_eq!(query.per_page, 0);
        assert!(query.filter_string.is_none());
    }

    // ------------------------------------------------------------------------
    // ScanResult domain type tests
    // ------------------------------------------------------------------------

    /// ScanResult serializes with camelCase fields and omits None.
    #[test]
    fn scan_result_serializes_camel_case() {
        let result = ScanResult {
            id: "result-1".to_string(),
            name: "Test NVT".to_string(),
            host: Some("192.168.1.1".to_string()),
            port: Some("443/tcp".to_string()),
            severity: Some(9.8),
            threat: Some("High".to_string()),
            nvt: Some(NvtRef {
                oid: Some("1.3.6.1.4.1.25623.1.0.12345".to_string()),
                name: Some("Test NVT".to_string()),
                family: Some("Test Family".to_string()),
                cvss_base: Some(9.8),
                cves: vec!["CVE-2024-1234".to_string()],
                tags: None,
            }),
            description: Some("A vulnerability was found.".to_string()),
            task: None,
            report: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"cvssBase\""));
        assert!(!json.contains("\"tags\""));
        assert!(!json.contains("\"task\""));
    }

    /// NvtRef omits empty cves array.
    #[test]
    fn nvt_ref_omits_empty_cves() {
        let nvt = NvtRef {
            oid: Some("1.2.3".to_string()),
            name: None,
            family: None,
            cvss_base: None,
            cves: vec![],
            tags: None,
        };
        let json = serde_json::to_string(&nvt).unwrap();
        assert!(!json.contains("\"cves\""));
    }

    /// ResultQuery defaults to zero page/per_page.
    #[test]
    fn result_query_default() {
        let query = ResultQuery::default();
        assert_eq!(query.page, 0);
        assert_eq!(query.per_page, 0);
        assert!(query.filter_string.is_none());
    }
}
