// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Live gvmd adapter backed by session-keyed GMP clients over Unix sockets.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::{
    AuthPort, CreateScanConfigInput, CreateTargetInput, CreateTaskInput, GatewayError,
    GetReportOpts, ModifyScanConfigInput, ModifyTargetInput, ModifyTaskInput, Pagination, Report,
    ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort, ResultQuery, ScanConfig,
    ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort,
    ScannerQuery, Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction, TaskPage,
    TaskPort, TaskQuery,
};
use gvm_gmp::{
    commands::{
        authentication::authenticate,
        reports::{delete_report, get_report, get_reports, GetReportsOpts},
        results::{get_result, get_results, GetResultsOpts},
        scan_configs::{
            create_scan_config, delete_scan_config, get_scan_config, get_scan_configs,
            modify_scan_config, ConfigOpts, GetScanConfigsOpts,
        },
        scanners::{get_scanner, get_scanners, GetScannersOpts},
        targets::{
            create_target, delete_target, get_target, get_targets, modify_target, CreateTargetOpts,
            GetTargetsOpts, ModifyTargetOpts,
        },
        tasks::{
            create_task, delete_task as delete_task_cmd, get_task as get_task_cmd, get_tasks,
            modify_task as modify_task_cmd, resume_task as resume_task_cmd,
            start_task as start_task_cmd, stop_task as stop_task_cmd, CreateTaskOpts, GetTasksOpts,
            ModifyTaskOpts,
        },
    },
    responses::{
        ActionResponse, CreateScanConfigResponse, CreateTargetResponse, CreateTaskResponse,
        GetReportsResponse, GetResultsResponse, GetScanConfigsResponse, GetScannersResponse,
        GetTargetsResponse, GetTasksResponse, StartTaskResponse,
    },
    EntityId,
};
use tokio::sync::Mutex as AsyncMutex;

use crate::conversions::{
    map_gvm_error, map_parse_error, parse_alive_test, parse_entity_id, parse_hosts_ordering,
    reject_unsupported_credentials, report_from_gmp, result_from_gmp, scan_config_from_gmp,
    scanner_from_gmp, target_from_gmp, task_from_gmp,
};

type SharedClient = Arc<AsyncMutex<GmpClient<UnixSocketConnection>>>;

/// gvmd adapter backed by session-keyed GMP clients.
#[derive(Clone, Debug)]
pub struct GvmdAdapter {
    socket_path: PathBuf,
    sessions: Arc<Mutex<HashMap<String, SharedClient>>>,
}

impl GvmdAdapter {
    /// Create a Unix-socket adapter.
    pub fn unix_socket(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Open and authenticate a session-bound GMP connection.
    pub async fn connect_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        let connection = UnixSocketConnection::with_path(&self.socket_path);
        let mut client = GmpClient::connect(connection)
            .await
            .map_err(map_gvm_error)?;
        client
            .call(authenticate(username, password))
            .await
            .map_err(map_gvm_error)?;

        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .insert(session_token.to_string(), Arc::new(AsyncMutex::new(client)));

        Ok(())
    }

    fn session_client(&self, session_token: &str) -> Result<SharedClient, GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .get(session_token)
            .cloned()
            .ok_or_else(|| GatewayError::Unauthorized("missing gvmd session".to_string()))
    }
}

#[async_trait]
impl TargetPort for GvmdAdapter {
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_targets(GetTargetsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(target_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(TargetPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        reject_unsupported_credentials(&input)?;
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_target(
                &input.name,
                CreateTargetOpts {
                    comment: input.comment,
                    hosts: input.hosts,
                    exclude_hosts: input.exclude_hosts,
                    alive_test: input
                        .alive_test
                        .as_deref()
                        .map(parse_alive_test)
                        .transpose()?,
                    port_list_id: input
                        .port_list_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                    reverse_lookup_only: input.reverse_lookup_only,
                    reverse_lookup_unify: input.reverse_lookup_unify,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateTargetResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_target(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(target_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("target {id} not found")))
    }

    async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        let client = self.session_client(session_token)?;
        let target_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await
            .call(modify_target(
                &target_id,
                ModifyTargetOpts {
                    name: input.name,
                    comment: input.comment,
                    hosts: input.hosts.unwrap_or_default(),
                    exclude_hosts: input.exclude_hosts.unwrap_or_default(),
                    alive_test: input
                        .alive_test
                        .as_deref()
                        .map(parse_alive_test)
                        .transpose()?,
                    port_list_id: input
                        .port_list_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_target(session_token, id).await
    }

    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_target(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl TaskPort for GvmdAdapter {
    async fn list_tasks(
        &self,
        session_token: &str,
        query: &TaskQuery,
    ) -> Result<TaskPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_tasks(GetTasksOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
                schedules_only: None,
                ignore_pagination: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(task_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(TaskPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_task(
        &self,
        session_token: &str,
        input: CreateTaskInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(&input.scan_config_id)?;
        let target_id = parse_entity_id(&input.target_id)?;
        let scanner_id = parse_entity_id(&input.scanner_id)?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .iter()
            .map(|id| parse_entity_id(id))
            .collect::<Result<Vec<_>, _>>()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = client
            .lock()
            .await
            .call(create_task(
                &input.name,
                &config_id,
                &target_id,
                &scanner_id,
                CreateTaskOpts {
                    alterable: input.alterable,
                    hosts_ordering,
                    schedule_id,
                    alert_ids,
                    comment: input.comment,
                    schedule_periods: input.schedule_periods,
                    observers: input.observers,
                    preferences: input.preferences,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateTaskResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_task_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(task_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("task {id} not found")))
    }

    async fn modify_task(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        let client = self.session_client(session_token)?;
        let task_id = parse_entity_id(id)?;
        let target_id = input
            .target_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let config_id = input
            .scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let scanner_id = input
            .scanner_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let schedule_id = input
            .schedule_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let alert_ids = input
            .alert_ids
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let hosts_ordering = input
            .hosts_ordering
            .as_deref()
            .map(parse_hosts_ordering)
            .transpose()?;

        let response = client
            .lock()
            .await
            .call(modify_task_cmd(
                &task_id,
                ModifyTaskOpts {
                    name: input.name,
                    comment: input.comment,
                    alterable: None,
                    hosts_ordering,
                    schedule_id,
                    schedule_periods: input.schedule_periods,
                    target_id,
                    config_id,
                    scanner_id,
                    alert_ids,
                    observers: input.observers,
                    preferences: vec![],
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_task(session_token, id).await
    }

    async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_task_cmd(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(start_task_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = StartTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(stop_task_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(resume_task_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        // resume_task returns ActionResponse (no report_id field) in rust-gvm,
        // but the GMP protocol does return a report_id. Parse as StartTaskResponse
        // which shares the same XML structure.
        let parsed = StartTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("resume_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }
}

#[async_trait]
impl ReportPort for GvmdAdapter {
    async fn list_reports(
        &self,
        session_token: &str,
        query: &ReportQuery,
    ) -> Result<ReportPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_reports(GetReportsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                details: Some(true),
                ignore_pagination: None,
                no_report: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(report_from_gmp)
            .collect::<Vec<_>>();

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(ReportPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn get_report(
        &self,
        session_token: &str,
        id: &str,
        opts: &GetReportOpts,
    ) -> Result<Report, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(id)?;

        // Get the report with details
        let response = client
            .lock()
            .await
            .call(get_report(&report_id))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut report = parsed
            .items
            .into_iter()
            .next()
            .map(report_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("report {id} not found")))?;

        // Fetch results for this report
        let filter = if opts.ignore_pagination {
            Some(format!("report_id={id}"))
        } else {
            Some(format!("report_id={id} first=25 rows=25"))
        };

        let results_response = client
            .lock()
            .await
            .call(get_results(GetResultsOpts {
                filter_string: filter,
                filter_id: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let results_parsed =
            GetResultsResponse::from_response(&results_response).map_err(map_parse_error)?;
        report.results = results_parsed
            .items
            .into_iter()
            .map(result_from_gmp)
            .collect();

        Ok(report)
    }

    async fn delete_report(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_report(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn get_report_results(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
        // Validate that the report_id is a valid UUID
        let _ = parse_entity_id(report_id)?;

        let filter = {
            let mut parts = vec![format!("report_id={report_id}")];
            if let Some(ref filter_string) = query.filter_string {
                if !filter_string.trim().is_empty() {
                    parts.push(filter_string.clone());
                }
            }
            Some(parts.join(" "))
        };

        let response = client
            .lock()
            .await
            .call(get_results(GetResultsOpts {
                filter_string: filter,
                filter_id: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetResultsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(result_from_gmp)
            .collect::<Vec<_>>();

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(ResultPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }
}

#[async_trait]
impl ResultPort for GvmdAdapter {
    async fn list_results(
        &self,
        session_token: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_results(GetResultsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetResultsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(result_from_gmp)
            .collect::<Vec<_>>();

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(ResultPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn get_result(&self, session_token: &str, id: &str) -> Result<ScanResult, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_result(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetResultsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(result_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("result {id} not found")))
    }
}

#[async_trait]
impl ScanConfigPort for GvmdAdapter {
    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_scan_configs(GetScanConfigsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(ScanConfigPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let base_id = input
            .base_scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(create_scan_config(
                &input.name,
                base_id.as_ref(),
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScanConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_scan_config(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(scan_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("scan config {id} not found")))
    }

    async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await
            .call(modify_scan_config(
                &config_id,
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_scan_config(session_token, id).await
    }

    async fn delete_scan_config(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_scan_config(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl ScannerPort for GvmdAdapter {
    async fn list_scanners(
        &self,
        session_token: &str,
        query: &ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_scanners(GetScannersOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScannersResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(scanner_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        let data = items
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect::<Vec<_>>();

        Ok(ScannerPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn get_scanner(&self, session_token: &str, id: &str) -> Result<Scanner, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_scanner(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScannersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(scanner_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("scanner {id} not found")))
    }
}

#[async_trait]
impl AuthPort for GvmdAdapter {
    async fn authenticate_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        self.connect_session(session_token, username, password)
            .await
    }

    async fn disconnect_session(&self, session_token: &str) -> Result<(), GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .remove(session_token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gvmd_adapter_session_client_fails_without_session() {
        let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
        let result = adapter.session_client("missing-token");
        assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
    }

    mod integration {
        use super::*;
        use gvm_gateway_domain::{CreateTargetInput, ModifyTargetInput, TargetQuery};
        use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, Resource, ServerMode};

        async fn create_mock_adapter() -> (GvmdAdapter, MockGmpServer, String) {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-session-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            (adapter, server, token.to_string())
        }

        #[tokio::test]
        async fn gvmd_adapter_connect_session_success() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let result = adapter.connect_session("token", "admin", "admin").await;

            assert!(result.is_ok());
            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_empty() {
            let (adapter, server, token) = create_mock_adapter().await;

            let result = adapter
                .list_targets(
                    &token,
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert!(page.data.is_empty());
            assert_eq!(page.pagination.total, 0);

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_create_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            let input = CreateTargetInput {
                name: "Test Target".to_string(),
                comment: Some("Integration test".to_string()),
                hosts: vec!["192.168.1.1".to_string()],
                exclude_hosts: vec![],
                alive_test: None,
                port_list_id: None,
                reverse_lookup_only: None,
                reverse_lookup_unify: None,
                ssh_credential_id: None,
                smb_credential_id: None,
                esxi_credential_id: None,
                snmp_credential_id: None,
            };

            let result = adapter.create_target(&token, input).await;

            assert!(result.is_ok());
            let id = result.unwrap();
            assert!(!id.is_empty());

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Get Me".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
                exclude_hosts: vec![],
                alive_test: None,
                port_list_id: None,
                reverse_lookup_only: None,
                reverse_lookup_unify: None,
                ssh_credential_id: None,
                smb_credential_id: None,
                esxi_credential_id: None,
                snmp_credential_id: None,
            };
            let id = adapter.create_target(&token, input).await.unwrap();

            // Fetch the target
            let result = adapter.get_target(&token, &id).await;

            assert!(result.is_ok());
            let target = result.unwrap();
            assert_eq!(target.name, "Get Me");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_target_not_found() {
            let (adapter, server, token) = create_mock_adapter().await;

            let result = adapter
                .get_target(&token, "550e8400-e29b-41d4-a716-446655440000")
                .await;

            assert!(matches!(result, Err(GatewayError::NotFound(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_modify_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Before Modify".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
                exclude_hosts: vec![],
                alive_test: None,
                port_list_id: None,
                reverse_lookup_only: None,
                reverse_lookup_unify: None,
                ssh_credential_id: None,
                smb_credential_id: None,
                esxi_credential_id: None,
                snmp_credential_id: None,
            };
            let id = adapter.create_target(&token, input).await.unwrap();

            // Modify the target
            let modify_input = ModifyTargetInput {
                name: Some("After Modify".to_string()),
                comment: Some("Updated".to_string()),
                hosts: Some(vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()]),
                exclude_hosts: None,
                alive_test: None,
                port_list_id: None,
            };
            let result = adapter.modify_target(&token, &id, modify_input).await;

            assert!(result.is_ok());
            let target = result.unwrap();
            assert_eq!(target.name, "After Modify");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_delete_target() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Create a target first
            let input = CreateTargetInput {
                name: "Delete Me".to_string(),
                comment: None,
                hosts: vec!["10.0.0.1".to_string()],
                exclude_hosts: vec![],
                alive_test: None,
                port_list_id: None,
                reverse_lookup_only: None,
                reverse_lookup_unify: None,
                ssh_credential_id: None,
                smb_credential_id: None,
                esxi_credential_id: None,
                snmp_credential_id: None,
            };
            let id = adapter.create_target(&token, input).await.unwrap();

            // Delete the target
            let result = adapter.delete_target(&token, &id).await;

            assert!(result.is_ok());

            // Verify it's gone
            let get_result = adapter.get_target(&token, &id).await;
            assert!(matches!(get_result, Err(GatewayError::NotFound(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_paginated() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .seed(|store| {
                    for i in 1..=15 {
                        let mut resource = Resource::new("target", &format!("Target-{i:02}"));
                        resource.set_attr("hosts", &format!("10.0.0.{i}"));
                        store.create(resource);
                    }
                })
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            let result = adapter
                .list_targets(
                    token,
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 10,
                    },
                )
                .await;

            assert!(result.is_ok());
            let page = result.unwrap();
            assert_eq!(page.data.len(), 10);
            assert_eq!(page.pagination.total, 15);
            assert_eq!(page.pagination.total_pages, 2);

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_unauthorized() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            // Don't authenticate

            let result = adapter
                .list_targets(
                    "unauthed-token",
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;

            assert!(matches!(result, Err(GatewayError::Unauthorized(_))));

            server.shutdown().await;
        }
    }
}
