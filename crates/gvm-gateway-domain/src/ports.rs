// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port traits describing backend-facing gateway operations.

use async_trait::async_trait;

use crate::{
    CreateScanConfigInput, CreateTargetInput, CreateTaskInput, GatewayError, GetReportOpts,
    ModifyScanConfigInput, ModifyTargetInput, ModifyTaskInput, ReadinessStatus, Report, ReportPage,
    ReportQuery, ResultPage, ResultQuery, ScanConfig, ScanConfigPage, ScanConfigQuery, ScanResult,
    Scanner, ScannerPage, ScannerQuery, Target, TargetPage, TargetQuery, Task, TaskAction,
    TaskPage, TaskQuery,
};

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

/// Port for scan config CRUD operations.
#[async_trait]
pub trait ScanConfigPort: Send + Sync + 'static {
    /// List scan configs for the session.
    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError>;

    /// Create a new scan config.
    async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a scan config by identifier.
    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError>;

    /// Modify a scan config by identifier.
    async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError>;

    /// Delete a scan config by identifier.
    async fn delete_scan_config(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;
}

/// Port for scanner read operations.
#[async_trait]
pub trait ScannerPort: Send + Sync + 'static {
    /// List scanners for the session.
    async fn list_scanners(
        &self,
        session_token: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError>;

    /// Fetch a scanner by identifier.
    async fn get_scanner(&self, session_token: &str, id: &str) -> Result<Scanner, GatewayError>;
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

/// Port for task CRUD and lifecycle operations.
#[async_trait]
pub trait TaskPort: Send + Sync + 'static {
    /// List tasks for the session.
    async fn list_tasks(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError>;

    /// Create a new task.
    async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError>;

    /// Fetch a task by identifier.
    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError>;

    /// Modify a task by identifier.
    async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError>;

    /// Delete a task by identifier.
    async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Start a task. Returns the report identifier created by the action.
    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError>;

    /// Stop a running task.
    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError>;

    /// Resume a stopped task. Returns the report identifier created by the action.
    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError>;
}
