// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Live gvmd adapter backed by session-keyed GMP clients over Unix sockets.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::{
    Alert, AlertPage, AlertPort, AlertQuery, AuthPort, CreateAlertInput, CreateCredentialInput,
    CreateGroupInput, CreatePermissionInput, CreatePortListInput, CreateRoleInput,
    CreateScanConfigInput, CreateScheduleInput, CreateTargetInput, CreateTaskInput,
    CreateUserInput, Credential, CredentialPage, CredentialPort, CredentialQuery, CredentialStore,
    Feed, FeedPort, GatewayError, GetReportOpts, Group, GroupPage, IdentityPort, IdentityQuery,
    ModifyAlertInput, ModifyCredentialInput, ModifyGroupInput, ModifyPermissionInput,
    ModifyPortListInput, ModifyRoleInput, ModifyScanConfigInput, ModifyScheduleInput,
    ModifyTargetInput, ModifyTaskInput, ModifyUserInput, ModifyUserSettingInput, Pagination,
    Permission, PermissionPage, PortList, PortListPage, PortListPort, PortListQuery,
    ReadinessStatus, Report, ReportExport, ReportPage, ReportPort, ReportQuery, ResultPage,
    ResultPort, ResultQuery, Role, RolePage, ScanConfig, ScanConfigPage, ScanConfigPort,
    ScanConfigQuery, ScanResult, Scanner, ScannerPage, ScannerPort, ScannerQuery, Schedule,
    SchedulePage, SchedulePort, ScheduleQuery, SystemPort, Target, TargetPage, TargetPort,
    TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery, Timezone, TlsCertificate,
    TlsCertificatePage, User, UserPage, UserSetting, UserSettingList, UserSettingQuery,
};
use gvm_gmp::{
    commands::{
        alerts::{
            create_alert, delete_alert, get_alert, get_alerts, modify_alert, AlertOpts,
            GetAlertsOpts,
        },
        authentication::authenticate,
        credentials::{
            create_credential, delete_credential, get_credential, get_credentials,
            modify_credential, CredentialOpts, GetCredentialsOpts,
        },
        feed::get_feeds,
        groups::{
            create_group, delete_group, get_group, get_groups, modify_group, GetGroupsOpts,
            GroupOpts,
        },
        permissions::{
            create_permission, delete_permission, get_permission, get_permissions,
            modify_permission, GetPermissionsOpts, PermissionOpts,
        },
        port_lists::{
            create_port_list, delete_port_list, get_port_list, get_port_lists, modify_port_list,
            GetPortListsOpts, PortListOpts,
        },
        reports::{delete_report, get_report, get_reports, GetReportsOpts},
        results::{get_result, get_results, GetResultsOpts},
        roles::{
            create_role, delete_role, get_role, get_roles, modify_role, GetRolesOpts, RoleOpts,
        },
        scan_configs::{
            create_scan_config, delete_scan_config, get_scan_config, get_scan_configs,
            modify_scan_config, ConfigOpts, GetScanConfigsOpts,
        },
        scanners::{get_scanner, get_scanners, GetScannersOpts},
        schedules::{
            create_schedule, delete_schedule, get_schedule, get_schedules, modify_schedule,
            GetSchedulesOpts, ScheduleOpts,
        },
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
        user_settings::{
            get_user_setting, get_user_settings, modify_user_setting, GetUserSettingsOpts,
            ModifyUserSettingOpts,
        },
        users::{
            create_user, delete_user, get_user, get_users, modify_user, GetUsersOpts, UserOpts,
        },
    },
    responses::{
        ActionResponse, CreateAlertResponse, CreateCredentialResponse, CreateGroupResponse,
        CreatePermissionResponse, CreatePortListResponse, CreateRoleResponse,
        CreateScanConfigResponse, CreateScheduleResponse, CreateTargetResponse, CreateTaskResponse,
        CreateUserResponse, GetAlertsResponse, GetCredentialsResponse, GetFeedsResponse,
        GetGroupsResponse, GetPermissionsResponse, GetPortListsResponse, GetReportsResponse,
        GetResultsResponse, GetRolesResponse, GetScanConfigsResponse, GetScannersResponse,
        GetSchedulesResponse, GetTargetsResponse, GetTasksResponse, GetUserSettingsResponse,
        GetUsersResponse, GetVersionResponse, ModifyUserSettingResponse, StartTaskResponse,
    },
    EntityId,
};
use gvm_protocol::{Request, Response};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{field, info_span, Instrument};

use crate::conversions::{
    alert_from_gmp, credential_from_gmp, feed_from_gmp, group_from_gmp, map_gvm_error,
    map_parse_error, parse_alert_condition, parse_alert_event, parse_alert_method,
    parse_alive_test, parse_credential_type, parse_entity_id, parse_hosts_ordering,
    parse_permission_subject_type, parse_snmp_auth_algorithm, parse_snmp_privacy_algorithm,
    parse_user_auth_type, permission_from_gmp, port_list_from_gmp, reject_unsupported_credentials,
    report_from_gmp, result_from_gmp, role_from_gmp, scan_config_from_gmp, scanner_from_gmp,
    schedule_from_gmp, target_from_gmp, task_from_gmp, user_from_gmp, user_setting_from_gmp,
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

    /// Probe the backend GMP version without creating a session-bound client.
    pub async fn probe_version(&self) -> Result<String, GatewayError> {
        let span = info_span!(
            "gvmd.probe_version",
            otel_name = "gvmd.probe_version",
            gvmd_endpoint = %self.socket_path.display()
        );

        async move {
            let connection = UnixSocketConnection::with_path(&self.socket_path);
            let mut client = GmpClient::connect(connection)
                .await
                .map_err(map_gvm_error)?;
            let negotiated = client.version().to_string();
            let response = client
                .call(gvm_gmp::commands::version::get_version())
                .await
                .map_err(map_gvm_error)?;
            let parsed = GetVersionResponse::from_response(&response).map_err(map_parse_error)?;

            if parsed.version.trim().is_empty() {
                Ok(negotiated)
            } else {
                Ok(parsed.version)
            }
        }
        .instrument(span)
        .await
    }

    /// Open and authenticate a session-bound GMP connection.
    pub async fn connect_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        let span = info_span!(
            "gvmd.session.connect",
            otel_name = "gvmd.session.connect",
            gvmd_username = %username,
            session_id = %safe_session_id(session_token),
            gvmd_endpoint = %self.socket_path.display()
        );

        async move {
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
                .map_err(|_| {
                    GatewayError::BackendUnavailable("session store unavailable".to_string())
                })?
                .insert(session_token.to_string(), Arc::new(AsyncMutex::new(client)));

            Ok(())
        }
        .instrument(span)
        .await
    }

    fn session_client(&self, session_token: &str) -> Result<SharedClient, GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .get(session_token)
            .cloned()
            .ok_or_else(|| GatewayError::SessionInvalidated("missing gvmd session".to_string()))
    }

    async fn call_with_session<R: Request>(
        &self,
        session_token: &str,
        operation: &'static str,
        request: R,
    ) -> Result<Response, GatewayError> {
        let client = self.session_client(session_token)?;
        let span = info_span!(
            "gvmd.request",
            otel_name = "gvmd.request",
            session_id = %safe_session_id(session_token),
            gvmd_operation = operation,
            gvmd_endpoint = %self.socket_path.display(),
            gvmd_status = field::Empty,
        );

        async move {
            let response = client
                .lock()
                .await
                .call(request)
                .await
                .map_err(map_gvm_error)?;
            tracing::Span::current().record("gvmd_status", field::display("ok"));
            Ok(response)
        }
        .instrument(span)
        .await
    }

    fn spawn_feed_sync(&self) -> Result<(), GatewayError> {
        let bin = std::env::var("GVM_GATEWAY_FEED_SYNC_BIN")
            .unwrap_or_else(|_| "greenbone-feed-sync".to_string());
        ProcessCommand::new(bin)
            .spawn()
            .map(|_| ())
            .map_err(|error| {
                GatewayError::BackendUnavailable(format!("failed to start feed sync: {error}"))
            })
    }

    fn load_timezones(&self) -> Vec<Timezone> {
        for path in [
            "/usr/share/zoneinfo/zone1970.tab",
            "/usr/share/zoneinfo/zone.tab",
        ] {
            if let Ok(contents) = fs::read_to_string(path) {
                let mut zones = contents
                    .lines()
                    .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
                    .filter_map(|line| {
                        let mut fields = line.split('\t');
                        let _country_codes = fields.next()?;
                        let _coordinates = fields.next()?;
                        let name = fields.next()?.trim();
                        Some(Timezone {
                            name: name.to_string(),
                            display_name: Some(name.replace('_', " ")),
                        })
                    })
                    .collect::<Vec<_>>();

                if !zones.is_empty() {
                    zones.sort_by(|left, right| left.name.cmp(&right.name));
                    zones.dedup_by(|left, right| left.name == right.name);
                    return zones;
                }
            }
        }

        vec![Timezone {
            name: "UTC".to_string(),
            display_name: Some("UTC".to_string()),
        }]
    }

    fn default_credential_stores(&self) -> Vec<CredentialStore> {
        vec![CredentialStore {
            id: "default".to_string(),
            name: "Default".to_string(),
            provider: Some("gvmd".to_string()),
            default: true,
            writable: true,
        }]
    }
}

fn safe_session_id(token: &str) -> String {
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

fn paged_pagination(total: u32, page: u32, per_page: u32) -> Pagination {
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / per_page) + 1
    };

    Pagination {
        page,
        per_page,
        total,
        total_pages,
    }
}

fn paged_slice<T>(items: Vec<T>, page: u32, per_page: u32) -> Vec<T> {
    let start = ((page.saturating_sub(1)) * per_page) as usize;
    items
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect()
}

#[async_trait]
impl AlertPort for GvmdAdapter {
    async fn list_alerts(
        &self,
        session_token: &str,
        query: &AlertQuery,
    ) -> Result<AlertPage, GatewayError> {
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
            .call(get_alerts(GetAlertsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAlertsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(alert_from_gmp)
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

        Ok(AlertPage {
            data,
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_alert(
        &self,
        session_token: &str,
        input: CreateAlertInput,
    ) -> Result<String, GatewayError> {
        if !input.event_data.is_empty()
            || !input.condition_data.is_empty()
            || !input.method_data.is_empty()
        {
            return Err(GatewayError::InvalidInput(
                "alert eventData/conditionData/methodData are not supported by the current GMP adapter".to_string(),
            ));
        }
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_alert(
                &input.name,
                AlertOpts {
                    comment: input.comment,
                    event: input.event.as_deref().map(parse_alert_event).transpose()?,
                    condition: input
                        .condition
                        .as_deref()
                        .map(parse_alert_condition)
                        .transpose()?,
                    method: input
                        .method
                        .as_deref()
                        .map(parse_alert_method)
                        .transpose()?,
                    filter_id: input
                        .filter_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateAlertResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_alert(&self, session_token: &str, id: &str) -> Result<Alert, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_alert(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAlertsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(alert_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("alert {id} not found")))
    }

    async fn modify_alert(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        if input
            .event_data
            .as_ref()
            .is_some_and(|value| !value.is_empty())
            || input
                .condition_data
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            || input
                .method_data
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        {
            return Err(GatewayError::InvalidInput(
                "alert eventData/conditionData/methodData are not supported by the current GMP adapter".to_string(),
            ));
        }
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_alert(
                &parse_entity_id(id)?,
                AlertOpts {
                    comment: input.comment,
                    event: input.event.as_deref().map(parse_alert_event).transpose()?,
                    condition: input
                        .condition
                        .as_deref()
                        .map(parse_alert_condition)
                        .transpose()?,
                    method: input
                        .method
                        .as_deref()
                        .map(parse_alert_method)
                        .transpose()?,
                    filter_id: input
                        .filter_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_alert(session_token, id).await
    }

    async fn delete_alert(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_alert(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl SchedulePort for GvmdAdapter {
    async fn list_timezones(&self, _: &str) -> Result<Vec<Timezone>, GatewayError> {
        Ok(self.load_timezones())
    }

    async fn list_schedules(
        &self,
        session_token: &str,
        query: &ScheduleQuery,
    ) -> Result<SchedulePage, GatewayError> {
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
            .call(get_schedules(GetSchedulesOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
                tasks: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetSchedulesResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(schedule_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        Ok(SchedulePage {
            data: items
                .into_iter()
                .skip(start)
                .take(query.per_page as usize)
                .collect(),
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_schedule(
        &self,
        session_token: &str,
        input: CreateScheduleInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_schedule(
                &input.name,
                ScheduleOpts {
                    comment: input.comment,
                    icalendar: Some(input.icalendar),
                    timezone: Some(input.timezone),
                    name: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScheduleResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_schedule(&self, session_token: &str, id: &str) -> Result<Schedule, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_schedule(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetSchedulesResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(schedule_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("schedule {id} not found")))
    }

    async fn modify_schedule(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScheduleInput,
    ) -> Result<Schedule, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_schedule(
                &parse_entity_id(id)?,
                ScheduleOpts {
                    comment: input.comment,
                    icalendar: input.icalendar,
                    timezone: input.timezone,
                    name: input.name,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_schedule(session_token, id).await
    }

    async fn delete_schedule(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_schedule(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl CredentialPort for GvmdAdapter {
    async fn list_credential_stores(&self, _: &str) -> Result<Vec<CredentialStore>, GatewayError> {
        Ok(self.default_credential_stores())
    }

    async fn list_credentials(
        &self,
        session_token: &str,
        query: &CredentialQuery,
    ) -> Result<CredentialPage, GatewayError> {
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
            .call(get_credentials(GetCredentialsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(credential_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        Ok(CredentialPage {
            data: items
                .into_iter()
                .skip(start)
                .take(query.per_page as usize)
                .collect(),
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_credential(
        &self,
        session_token: &str,
        input: CreateCredentialInput,
    ) -> Result<String, GatewayError> {
        if input.private_key.is_some()
            || input.certificate.is_some()
            || input.privacy_password.is_some()
        {
            return Err(GatewayError::InvalidInput(
                "privateKey, certificate, and privacyPassword are not supported by the current GMP adapter".to_string(),
            ));
        }
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_credential(
                &input.name,
                CredentialOpts {
                    comment: input.comment,
                    credential_type: Some(parse_credential_type(&input.credential_type)?),
                    login: input.login,
                    password: input.password.or(input.community),
                    private_key: None,
                    certificate: None,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    format: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateCredentialResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_credential(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Credential, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_credential(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(credential_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("credential {id} not found")))
    }

    async fn modify_credential(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyCredentialInput,
    ) -> Result<Credential, GatewayError> {
        if input.private_key.is_some()
            || input.certificate.is_some()
            || input.privacy_password.is_some()
        {
            return Err(GatewayError::InvalidInput(
                "privateKey, certificate, and privacyPassword are not supported by the current GMP adapter".to_string(),
            ));
        }
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_credential(
                &parse_entity_id(id)?,
                CredentialOpts {
                    comment: input.comment,
                    credential_type: None,
                    login: input.login,
                    password: input.password.or(input.community),
                    private_key: None,
                    certificate: None,
                    auth_algorithm: input
                        .auth_algorithm
                        .as_deref()
                        .map(parse_snmp_auth_algorithm)
                        .transpose()?,
                    privacy_algorithm: input
                        .privacy_algorithm
                        .as_deref()
                        .map(parse_snmp_privacy_algorithm)
                        .transpose()?,
                    format: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_credential(session_token, id).await
    }

    async fn delete_credential(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_credential(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl PortListPort for GvmdAdapter {
    async fn list_port_lists(
        &self,
        session_token: &str,
        query: &PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
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
            .call(get_port_lists(GetPortListsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPortListsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(port_list_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        let total_pages = if total == 0 {
            0
        } else {
            ((total - 1) / query.per_page) + 1
        };
        let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;
        Ok(PortListPage {
            data: items
                .into_iter()
                .skip(start)
                .take(query.per_page as usize)
                .collect(),
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total,
                total_pages,
            },
        })
    }

    async fn create_port_list(
        &self,
        session_token: &str,
        input: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_port_list(
                &input.name,
                PortListOpts {
                    comment: input.comment,
                    port_range: input.port_range,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreatePortListResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_port_list(&self, session_token: &str, id: &str) -> Result<PortList, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_port_list(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPortListsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(port_list_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("port list {id} not found")))
    }

    async fn modify_port_list(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_port_list(
                &parse_entity_id(id)?,
                PortListOpts {
                    comment: input.comment,
                    port_range: input.port_range,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_port_list(session_token, id).await
    }

    async fn delete_port_list(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_port_list(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

#[async_trait]
impl FeedPort for GvmdAdapter {
    async fn list_feeds(&self, session_token: &str) -> Result<Vec<Feed>, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_feeds())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFeedsResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.items.into_iter().map(feed_from_gmp).collect())
    }

    async fn sync_feeds(&self, _session_token: &str) -> Result<(), GatewayError> {
        self.spawn_feed_sync()
    }
}

#[async_trait]
impl IdentityPort for GvmdAdapter {
    async fn list_users(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<UserPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.list",
                get_users(GetUsersOpts {
                    filter_string: query.filter_string.clone(),
                    filter_id,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(user_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.meta.name.cmp(&right.meta.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);

        Ok(UserPage {
            data: paged_slice(items, query.page, query.per_page),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_user(
        &self,
        session_token: &str,
        input: CreateUserInput,
    ) -> Result<String, GatewayError> {
        let role_ids = input
            .role_ids
            .into_iter()
            .map(|value| parse_entity_id(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_type = input
            .authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.create",
                create_user(
                    &input.name,
                    UserOpts {
                        comment: input.comment,
                        password: input.password,
                        host_access: input.hosts,
                        role_ids,
                        auth_type,
                    },
                ),
            )
            .await?;
        let parsed = CreateUserResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_user(&self, session_token: &str, id: &str) -> Result<User, GatewayError> {
        let response = self
            .call_with_session(session_token, "users.get", get_user(&parse_entity_id(id)?))
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        let user = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("user {id} not found")))?;
        Ok(user_from_gmp(user))
    }

    async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        let role_ids = input
            .role_ids
            .unwrap_or_default()
            .into_iter()
            .map(|value| parse_entity_id(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_type = input
            .authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.modify",
                modify_user(
                    &parse_entity_id(id)?,
                    UserOpts {
                        comment: input.comment,
                        password: input.password,
                        host_access: input.hosts,
                        role_ids,
                        auth_type,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_user(session_token, id).await
    }

    async fn delete_user(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "users.delete",
                delete_user(&parse_entity_id(id)?, true),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_groups(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<GroupPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "groups.list",
                get_groups(GetGroupsOpts {
                    filter_string: query.filter_string.clone(),
                    filter_id,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(group_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.meta.name.cmp(&right.meta.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);

        Ok(GroupPage {
            data: paged_slice(items, query.page, query.per_page),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_group(
        &self,
        session_token: &str,
        input: CreateGroupInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_group(
                &input.name,
                GroupOpts {
                    comment: input.comment,
                    users: input.users,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateGroupResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_group(&self, session_token: &str, id: &str) -> Result<Group, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_group(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let group = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("group {id} not found")))?;
        Ok(group_from_gmp(group))
    }

    async fn modify_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_group(
                &parse_entity_id(id)?,
                GroupOpts {
                    comment: input.comment,
                    users: input.users.unwrap_or_default(),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_group(session_token, id).await
    }

    async fn delete_group(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_group(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_roles(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<RolePage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_roles(GetRolesOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetRolesResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(role_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.meta.name.cmp(&right.meta.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);

        Ok(RolePage {
            data: paged_slice(items, query.page, query.per_page),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_role(
        &self,
        session_token: &str,
        input: CreateRoleInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_role(
                &input.name,
                RoleOpts {
                    comment: input.comment,
                    users: input.users,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateRoleResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_role(&self, session_token: &str, id: &str) -> Result<Role, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_role(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetRolesResponse::from_response(&response).map_err(map_parse_error)?;
        let role = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("role {id} not found")))?;
        Ok(role_from_gmp(role))
    }

    async fn modify_role(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_role(
                &parse_entity_id(id)?,
                RoleOpts {
                    comment: input.comment,
                    users: input.users.unwrap_or_default(),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_role(session_token, id).await
    }

    async fn delete_role(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_role(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_permissions(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = client
            .lock()
            .await
            .call(get_permissions(GetPermissionsOpts {
                filter_string: query.filter_string.clone(),
                filter_id,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPermissionsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(permission_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.meta.name.cmp(&right.meta.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);

        Ok(PermissionPage {
            data: paged_slice(items, query.page, query.per_page),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_permission(
        &self,
        session_token: &str,
        input: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(create_permission(PermissionOpts {
                comment: input.comment,
                name: input.name,
                resource_id: input
                    .resource_id
                    .as_deref()
                    .map(parse_entity_id)
                    .transpose()?,
                resource_type: input.resource_type,
                subject_type: input
                    .subject_type
                    .as_deref()
                    .map(parse_permission_subject_type)
                    .transpose()?,
                subject_id: input
                    .subject_id
                    .as_deref()
                    .map(parse_entity_id)
                    .transpose()?,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreatePermissionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_permission(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Permission, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_permission(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPermissionsResponse::from_response(&response).map_err(map_parse_error)?;
        let permission = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("permission {id} not found")))?;
        Ok(permission_from_gmp(permission))
    }

    async fn modify_permission(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_permission(
                &parse_entity_id(id)?,
                PermissionOpts {
                    comment: input.comment,
                    name: input.name,
                    resource_id: input
                        .resource_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                    resource_type: input.resource_type,
                    subject_type: input
                        .subject_type
                        .as_deref()
                        .map(parse_permission_subject_type)
                        .transpose()?,
                    subject_id: input
                        .subject_id
                        .as_deref()
                        .map(parse_entity_id)
                        .transpose()?,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_permission(session_token, id).await
    }

    async fn delete_permission(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(delete_permission(&parse_entity_id(id)?, true))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_user_settings(
        &self,
        session_token: &str,
        query: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_user_settings(GetUserSettingsOpts {
                filter: query.filter_string.clone(),
                filter_id: query
                    .filter_id
                    .as_deref()
                    .map(parse_entity_id)
                    .transpose()?,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetUserSettingsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .settings
            .into_iter()
            .map(user_setting_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(UserSettingList { data: items })
    }

    async fn get_user_setting(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<UserSetting, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(get_user_setting(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetUserSettingsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .settings
            .into_iter()
            .next()
            .map(user_setting_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("user setting {id} not found")))
    }

    async fn modify_user_setting(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await
            .call(modify_user_setting(
                &parse_entity_id(id)?,
                ModifyUserSettingOpts { value: input.value },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ModifyUserSettingResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_user_setting(session_token, id).await
    }
}

#[async_trait]
impl TargetPort for GvmdAdapter {
    async fn list_targets(
        &self,
        session_token: &str,
        query: &TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "targets.list",
                get_targets(GetTargetsOpts {
                    filter_string: query.filter_string.clone(),
                    filter_id,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
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
        let response = self
            .call_with_session(
                session_token,
                "targets.create",
                create_target(
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
                ),
            )
            .await?;
        let parsed = CreateTargetResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "targets.get",
                get_target(&parse_entity_id(id)?),
            )
            .await?;
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
        let target_id = parse_entity_id(id)?;
        let response = self
            .call_with_session(
                session_token,
                "targets.modify",
                modify_target(
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
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_target(session_token, id).await
    }

    async fn delete_target(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "targets.delete",
                delete_target(&parse_entity_id(id)?, true),
            )
            .await?;
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
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "tasks.list",
                get_tasks(GetTasksOpts {
                    filter_string: query.filter_string.clone(),
                    filter_id,
                    trash: None,
                    details: Some(true),
                    schedules_only: None,
                    ignore_pagination: None,
                }),
            )
            .await?;
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

        let response = self
            .call_with_session(
                session_token,
                "tasks.create",
                create_task(
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
                ),
            )
            .await?;
        let parsed = CreateTaskResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_task(&self, session_token: &str, id: &str) -> Result<Task, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.get",
                get_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
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

        let response = self
            .call_with_session(
                session_token,
                "tasks.modify",
                modify_task_cmd(
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
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_task(session_token, id).await
    }

    async fn delete_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.delete",
                delete_task_cmd(&parse_entity_id(id)?, true),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn start_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.start",
                start_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let parsed = StartTaskResponse::from_response(&response).map_err(map_parse_error)?;
        let report_id = parsed.report_id.map(|id| id.to_string()).ok_or_else(|| {
            GatewayError::BackendUnavailable("start_task did not return a report_id".to_string())
        })?;
        Ok(TaskAction { report_id })
    }

    async fn stop_task(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.stop",
                stop_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn resume_task(&self, session_token: &str, id: &str) -> Result<TaskAction, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.resume",
                resume_task_cmd(&parse_entity_id(id)?),
            )
            .await?;
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

    async fn export_report(
        &self,
        session_token: &str,
        report_id: &str,
        report_format_id: &str,
    ) -> Result<ReportExport, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let report_format_id = parse_entity_id(report_format_id)?;

        let export = client
            .lock()
            .await
            .get_report_export(&report_id, &report_format_id)
            .await
            .map_err(map_gvm_error)?;

        Ok(ReportExport {
            bytes: export.bytes,
            content_type: export.content_type,
            extension: export.extension,
        })
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

    async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let page = self
            .get_report_results(session_token, report_id, &unpaginated_result_query(query))
            .await?;
        Ok(filter_result_page(page, query, |result| {
            result.nvt.is_some() || result.severity.is_some()
        }))
    }

    async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        let page = self
            .get_report_results(session_token, report_id, &unpaginated_result_query(query))
            .await?;
        let certificates = page
            .data
            .into_iter()
            .filter(is_tls_certificate_result)
            .map(|result| TlsCertificate {
                id: Some(result.id),
                host: result.host,
                port: result.port,
                subject: result.name,
                issuer: None,
                not_before: None,
                not_after: None,
                fingerprint_sha256: None,
            })
            .collect::<Vec<_>>();
        Ok(paginate_tls_certificates(certificates, query))
    }

    async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let page = self
            .get_report_results(session_token, report_id, &unpaginated_result_query(query))
            .await?;
        Ok(filter_result_page(page, query, is_error_result))
    }

    async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let page = self
            .get_report_results(session_token, report_id, &unpaginated_result_query(query))
            .await?;
        Ok(filter_result_page(page, query, is_closed_cve_result))
    }
}

fn unpaginated_result_query(query: &ResultQuery) -> ResultQuery {
    ResultQuery {
        filter_string: query.filter_string.clone(),
        filter_id: query.filter_id.clone(),
        page: 1,
        per_page: u32::MAX,
    }
}

fn filter_result_page(
    page: ResultPage,
    query: &ResultQuery,
    predicate: impl Fn(&ScanResult) -> bool,
) -> ResultPage {
    let filtered = page.data.into_iter().filter(predicate).collect::<Vec<_>>();
    paginate_results(filtered, query)
}

fn paginate_results(results: Vec<ScanResult>, query: &ResultQuery) -> ResultPage {
    let total = results.len() as u32;
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / query.per_page) + 1
    };
    let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;

    ResultPage {
        data: results
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect(),
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total,
            total_pages,
        },
    }
}

fn paginate_tls_certificates(
    certificates: Vec<TlsCertificate>,
    query: &ResultQuery,
) -> TlsCertificatePage {
    let total = certificates.len() as u32;
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / query.per_page) + 1
    };
    let start = ((query.page.saturating_sub(1)) * query.per_page) as usize;

    TlsCertificatePage {
        data: certificates
            .into_iter()
            .skip(start)
            .take(query.per_page as usize)
            .collect(),
        pagination: Pagination {
            page: query.page,
            per_page: query.per_page,
            total,
            total_pages,
        },
    }
}

fn is_error_result(result: &ScanResult) -> bool {
    result
        .threat
        .as_deref()
        .is_some_and(|threat| threat.eq_ignore_ascii_case("alarm"))
        || result_text(result).contains("error")
        || result_text(result).contains("failed")
}

fn is_closed_cve_result(result: &ScanResult) -> bool {
    let text = result_text(result);
    text.contains("closed cve") || text.contains("closed-cve") || text.contains("closed cves")
}

fn is_tls_certificate_result(result: &ScanResult) -> bool {
    let text = result_text(result);
    (text.contains("tls") || text.contains("ssl")) && text.contains("certificate")
}

fn result_text(result: &ScanResult) -> String {
    let mut text = result.name.to_ascii_lowercase();
    if let Some(description) = result.description.as_deref() {
        text.push(' ');
        text.push_str(&description.to_ascii_lowercase());
    }
    text
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
impl SystemPort for GvmdAdapter {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        match self.probe_version().await {
            Ok(_) => Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            }),
            Err(error) => Ok(ReadinessStatus {
                status: "notReady",
                reason: Some(error.detail().to_string()),
            }),
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        self.probe_version().await
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
    use std::{
        io,
        io::Write,
        sync::{Arc, Mutex, OnceLock},
    };

    use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
    use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt};

    use super::*;

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture_tracing() -> Arc<Mutex<Vec<u8>>> {
        static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        static INIT: OnceLock<()> = OnceLock::new();

        let buffer = BUFFER
            .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
            .clone();

        INIT.get_or_init(|| {
            let writer = buffer.clone();
            let subscriber = tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_span_events(FmtSpan::CLOSE)
                    .with_writer(move || SharedWriter(writer.clone())),
            );
            let _ = tracing::subscriber::set_global_default(subscriber);
        });

        buffer.lock().unwrap().clear();
        buffer
    }

    async fn lock_tracing() -> AsyncMutexGuard<'static, ()> {
        static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
    }

    #[test]
    fn gvmd_adapter_session_client_fails_without_session() {
        let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
        let result = adapter.session_client("missing-token");
        assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
    }

    #[tokio::test]
    async fn gvmd_adapter_probe_version_reports_mock_version() {
        use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

        let server = MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(MockVersion::V22_7)
            .unix_socket_auto()
            .build()
            .await
            .unwrap();

        let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
        let version = adapter.probe_version().await.unwrap();
        assert_eq!(version, "22.7");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn gvmd_adapter_readiness_reports_ready_when_probe_succeeds() {
        use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

        // Covers the production `/ready` contract: a reachable GMP backend must
        // be reported as ready instead of relying on startup-only state.
        let server = MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .version(MockVersion::V22_7)
            .unix_socket_auto()
            .build()
            .await
            .unwrap();

        let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
        let status = adapter.readiness().await.unwrap();
        assert_eq!(status.status, "ready");
        assert!(status.reason.is_none());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn gvmd_adapter_readiness_reports_not_ready_when_socket_is_missing() {
        // Regression coverage for compose startup races: `/ready` must degrade
        // while gvmd has not created its Unix socket yet.
        let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent-gvmd-readiness.sock");
        let status = adapter.readiness().await.unwrap();
        assert_eq!(status.status, "notReady");
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("socket not found")),
            "readiness reason should explain the missing socket: {:?}",
            status.reason
        );
    }

    mod integration {
        use super::*;
        use gvm_gateway_domain::{CreateTargetInput, ModifyTargetInput, TargetQuery};
        use gvm_mock_server::{
            response_gen::{REPORT_EXPORT_BINARY_FORMAT_ID, REPORT_EXPORT_XML_FORMAT_ID},
            GmpVersion as MockVersion, MockGmpServer, Resource, ServerMode,
        };

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
        async fn gvmd_adapter_emits_backend_boundary_spans_without_raw_session_token() {
            let _trace_lock = lock_tracing().await;
            let logs = capture_tracing();
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

            let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
            assert!(output.contains("gvmd.session.connect"));
            assert!(output.contains("gvmd.request"));
            assert!(output.contains("targets.list"));
            assert!(output.contains("session:"));
            assert!(!output.contains(&token));

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

            assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_export_report_binary_payload() {
            let report_id = uuid::Uuid::from_u128(0x11111111_1111_1111_1111_111111111111);
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_8)
                .unix_socket_auto()
                .seed(move |store| {
                    store.create(Resource::with_id(
                        "report",
                        "Binary export report",
                        report_id,
                    ));
                })
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-session-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            let export = adapter
                .export_report(
                    token,
                    &report_id.to_string(),
                    &REPORT_EXPORT_BINARY_FORMAT_ID.to_string(),
                )
                .await
                .expect("binary export");

            assert_eq!(export.bytes, b"Hello PDF");
            assert_eq!(export.content_type.as_deref(), Some("application/pdf"));
            assert_eq!(export.extension.as_deref(), Some("pdf"));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_export_report_xml_payload() {
            let report_id = uuid::Uuid::from_u128(0x22222222_2222_2222_2222_222222222222);
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_8)
                .unix_socket_auto()
                .seed(move |store| {
                    store.create(Resource::with_id("report", "XML export report", report_id));
                })
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let token = "test-session-token";
            adapter
                .connect_session(token, "admin", "admin")
                .await
                .unwrap();

            let export = adapter
                .export_report(
                    token,
                    &report_id.to_string(),
                    &REPORT_EXPORT_XML_FORMAT_ID.to_string(),
                )
                .await
                .expect("xml export");

            let xml = String::from_utf8(export.bytes).expect("utf8 xml");
            assert_eq!(export.content_type.as_deref(), Some("text/xml"));
            assert_eq!(export.extension.as_deref(), Some("xml"));
            assert!(xml.contains("<report id="));
            assert!(xml.contains(r#"<result id="result-1"/>"#));

            server.shutdown().await;
        }
    }
}
