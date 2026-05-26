// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::sync::Arc;

use async_trait::async_trait;
use gvm_gateway_domain::{
    Alert, AlertPage, AlertPort, AlertQuery, AuthPort, CreateAlertInput, CreateCredentialInput,
    CreatePortListInput, CreateScanConfigInput, CreateScheduleInput, CreateTargetInput,
    CreateTaskInput, Credential, CredentialPage, CredentialPort, CredentialQuery, Feed, FeedPort,
    GatewayError, GetReportOpts, ModifyAlertInput, ModifyCredentialInput, ModifyPortListInput,
    ModifyScanConfigInput, ModifyScheduleInput, ModifyTargetInput, ModifyTaskInput, PortList,
    PortListPage, PortListPort, PortListQuery, ReadinessStatus, Report, ReportPage, ReportPort,
    ReportQuery, ResultPage, ResultPort, ResultQuery, ScanConfig, ScanConfigPage, ScanConfigPort,
    ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort, ScannerQuery, Schedule,
    SchedulePage, SchedulePort, ScheduleQuery, SystemPort, Target, TargetPage, TargetPort,
    TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery,
};

/// Mock system port for tests that need deterministic readiness/version responses.
#[derive(Clone)]
pub(crate) struct MockSystemPort {
    pub(crate) ready: bool,
    pub(crate) gmp_version: String,
}

impl SystemPort for MockSystemPort {
    fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        if self.ready {
            Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            })
        } else {
            Ok(ReadinessStatus {
                status: "notReady",
                reason: Some("mock not ready".to_string()),
            })
        }
    }

    fn gmp_version(&self) -> Result<String, GatewayError> {
        Ok(self.gmp_version.clone())
    }
}

/// Mock alert port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockAlertPort;

#[async_trait]
impl AlertPort for MockAlertPort {
    async fn list_alerts(&self, _: &str, query: &AlertQuery) -> Result<AlertPage, GatewayError> {
        Ok(AlertPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_alert(&self, _: &str, _: CreateAlertInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000011".to_string())
    }

    async fn get_alert(&self, _: &str, id: &str) -> Result<Alert, GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn modify_alert(
        &self,
        _: &str,
        id: &str,
        _: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn delete_alert(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("alert {id} not found")))
    }
}

/// Mock schedule port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockSchedulePort;

#[async_trait]
impl SchedulePort for MockSchedulePort {
    async fn list_schedules(
        &self,
        _: &str,
        query: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
        Ok(SchedulePage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_schedule(
        &self,
        _: &str,
        _: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000012".to_string())
    }

    async fn get_schedule(&self, _: &str, id: &str) -> Result<Schedule, GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn modify_schedule(
        &self,
        _: &str,
        id: &str,
        _: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn delete_schedule(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("schedule {id} not found")))
    }
}

/// Mock credential port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockCredentialPort;

#[async_trait]
impl CredentialPort for MockCredentialPort {
    async fn list_credentials(
        &self,
        _: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
        Ok(CredentialPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_credential(
        &self,
        _: &str,
        _: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000013".to_string())
    }

    async fn get_credential(&self, _: &str, id: &str) -> Result<Credential, GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn modify_credential(
        &self,
        _: &str,
        id: &str,
        _: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn delete_credential(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("credential {id} not found")))
    }
}

/// Mock port-list port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockPortListPort;

#[async_trait]
impl PortListPort for MockPortListPort {
    async fn list_port_lists(
        &self,
        _: &str,
        query: &PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
        Ok(PortListPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_port_list(
        &self,
        _: &str,
        _: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000014".to_string())
    }

    async fn get_port_list(&self, _: &str, id: &str) -> Result<PortList, GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn modify_port_list(
        &self,
        _: &str,
        id: &str,
        _: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn delete_port_list(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("port list {id} not found")))
    }
}

/// Mock feed port for tests that only need wiring.
#[derive(Clone, Default)]
pub(crate) struct MockFeedPort;

#[async_trait]
impl FeedPort for MockFeedPort {
    async fn list_feeds(&self, _: &str) -> Result<Vec<Feed>, GatewayError> {
        Ok(vec![])
    }

    async fn sync_feeds(&self, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }
}

/// Mock target port for tests that validate session gating and audit behavior.
#[derive(Clone, Default)]
pub(crate) struct MockTargetPort {
    pub(crate) should_fail: bool,
}

#[async_trait]
impl TargetPort for MockTargetPort {
    async fn list_targets(
        &self,
        _session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::BackendUnavailable("mock error".to_string()));
        }
        Ok(TargetPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_target(
        &self,
        _session_token: &str,
        _input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::BackendUnavailable("mock error".to_string()));
        }
        Ok("mock-target-id".to_string())
    }

    async fn get_target(&self, _session_token: &str, id: &str) -> Result<Target, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(Target {
            id: id.to_string(),
            name: "Mock Target".to_string(),
            comment: None,
            hosts: vec!["10.0.0.1".to_string()],
            exclude_hosts: vec![],
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
        })
    }

    async fn modify_target(
        &self,
        _session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(Target {
            id: id.to_string(),
            name: input.name.unwrap_or_else(|| "Modified Target".to_string()),
            comment: input.comment,
            hosts: input.hosts.unwrap_or_else(|| vec!["10.0.0.1".to_string()]),
            exclude_hosts: input.exclude_hosts.unwrap_or_default(),
            alive_test: input.alive_test,
            port_list: None,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            ssh_credential: None,
            smb_credential: None,
            esxi_credential: None,
            snmp_credential: None,
            in_use: false,
            writable: true,
        })
    }

    async fn delete_target(&self, _session_token: &str, id: &str) -> Result<(), GatewayError> {
        if self.should_fail {
            return Err(GatewayError::NotFound(format!("target {id} not found")));
        }
        Ok(())
    }
}

/// Mock task port for tests that exercise task orchestration without backend state.
#[derive(Clone, Default)]
pub(crate) struct MockTaskPort;

#[async_trait]
impl TaskPort for MockTaskPort {
    async fn list_tasks(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Ok(TaskPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Ok("00000000-0000-0000-0000-000000000001".to_string())
    }

    async fn get_task(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
        Err(GatewayError::NotFound(format!("task {id} not found")))
    }

    async fn modify_task(
        &self,
        _: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        Ok(Task {
            id: id.to_string(),
            name: input.name.unwrap_or_else(|| "Modified Task".to_string()),
            comment: input.comment,
            status: "New".to_string(),
            target: None,
            scan_config: None,
            scanner: None,
            schedule: None,
            alerts: vec![],
            alterable: None,
            hosts_ordering: input.hosts_ordering,
            observers: input.observers,
            schedule_periods: input.schedule_periods,
            last_report: None,
            current_report: None,
            result_count: None,
            in_use: false,
            writable: true,
        })
    }

    async fn delete_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000002".to_string(),
        })
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Ok(())
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Ok(TaskAction {
            report_id: "00000000-0000-0000-0000-000000000003".to_string(),
        })
    }
}

/// Mock auth port for tests that need controlled auth and disconnect outcomes.
#[derive(Clone, Default)]
pub(crate) struct MockAuthPort {
    pub(crate) should_fail: bool,
    pub(crate) disconnect_should_fail: bool,
    pub(crate) disconnected: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl AuthPort for MockAuthPort {
    async fn authenticate_session(
        &self,
        _session_token: &str,
        _username: &str,
        _password: &str,
    ) -> Result<(), GatewayError> {
        if self.should_fail {
            return Err(GatewayError::Unauthorized(
                "invalid credentials".to_string(),
            ));
        }
        Ok(())
    }

    async fn disconnect_session(&self, session_token: &str) -> Result<(), GatewayError> {
        if self.disconnect_should_fail {
            return Err(GatewayError::BackendUnavailable(
                "disconnect failed".to_string(),
            ));
        }
        self.disconnected
            .lock()
            .unwrap()
            .push(session_token.to_string());
        Ok(())
    }
}

/// Mock report port for tests that validate report resource session flow.
#[derive(Clone, Default)]
pub(crate) struct MockReportPort;

#[async_trait]
impl ReportPort for MockReportPort {
    async fn list_reports(&self, _: &str, query: &ReportQuery) -> Result<ReportPage, GatewayError> {
        Ok(ReportPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_report(
        &self,
        _: &str,
        id: &str,
        _: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn delete_report(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!("report {id} not found")))
    }

    async fn get_report_results(
        &self,
        _: &str,
        _: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }
}

/// Mock result port for tests that validate result resource session flow.
#[derive(Clone, Default)]
pub(crate) struct MockResultPort;

#[async_trait]
impl ResultPort for MockResultPort {
    async fn list_results(&self, _: &str, query: &ResultQuery) -> Result<ResultPage, GatewayError> {
        Ok(ResultPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_result(&self, _: &str, id: &str) -> Result<ScanResult, GatewayError> {
        Err(GatewayError::NotFound(format!("result {id} not found")))
    }
}

/// Mock scan-config port for tests that validate scan-config session flow.
#[derive(Clone, Default)]
pub(crate) struct MockScanConfigPort;

#[async_trait]
impl ScanConfigPort for MockScanConfigPort {
    async fn list_scan_configs(
        &self,
        _: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        Ok(ScanConfigPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_scan_config(
        &self,
        _: &str,
        _: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        Ok("mock-scan-config-id".to_string())
    }

    async fn get_scan_config(&self, _: &str, id: &str) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }

    async fn modify_scan_config(
        &self,
        _: &str,
        id: &str,
        _: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }

    async fn delete_scan_config(&self, _: &str, id: &str) -> Result<(), GatewayError> {
        Err(GatewayError::NotFound(format!(
            "scan config {id} not found"
        )))
    }
}

/// Mock scanner port for tests that validate scanner read session flow.
#[derive(Clone, Default)]
pub(crate) struct MockScannerPort;

#[async_trait]
impl ScannerPort for MockScannerPort {
    async fn list_scanners(
        &self,
        _: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        Ok(ScannerPage {
            data: vec![],
            pagination: gvm_gateway_domain::Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn get_scanner(&self, _: &str, id: &str) -> Result<Scanner, GatewayError> {
        Err(GatewayError::NotFound(format!("scanner {id} not found")))
    }
}
