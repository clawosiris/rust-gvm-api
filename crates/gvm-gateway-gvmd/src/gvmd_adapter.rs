// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Live gvmd adapter backed by session-keyed GMP clients over Unix sockets.

use std::{
    collections::HashMap,
    fmt, fs,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gvm_client::{GetReportDetailsOpts, GmpClient};
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::{
    Alert, AlertPage, AlertPort, AlertQuery, AuthPort, CreateAlertInput, CreateCredentialInput,
    CreateGroupInput, CreateNoteInput, CreateOverrideInput, CreatePermissionInput,
    CreatePortListInput, CreateRoleInput, CreateScanConfigInput, CreateScheduleInput,
    CreateTargetInput, CreateTaskInput, CreateUserInput, Credential, CredentialPage,
    CredentialPort, CredentialQuery, CredentialStore, Feed, FeedPort, Filter, FilterPage,
    GatewayError, GetReportOpts, Group, GroupPage, Host, HostPage, IdentityPort, IdentityQuery,
    ModifyAlertInput, ModifyCredentialInput, ModifyGroupInput, ModifyNoteInput,
    ModifyOverrideInput, ModifyPermissionInput, ModifyPortListInput, ModifyRoleInput,
    ModifyScanConfigInput, ModifyScheduleInput, ModifyTargetInput, ModifyTaskInput,
    ModifyUserInput, ModifyUserSettingInput, Note, NotePage, Nvt, NvtFamilyPage, NvtPage, Override,
    OverridePage, Pagination, Permission, PermissionPage, PortList, PortListPage, PortListPort,
    PortListQuery, ReadinessStatus, Report, ReportExport, ReportFormat, ReportFormatPage,
    ReportPage, ReportPort, ReportQuery, ResultPage, ResultPort, ResultQuery, Role, RolePage,
    ScanConfig, ScanConfigPage, ScanConfigPort, ScanConfigQuery, ScanResult, Scanner, ScannerPage,
    ScannerPort, ScannerQuery, Schedule, SchedulePage, SchedulePort, ScheduleQuery,
    SessionTokenDigest, SupportingResourcePort, SupportingResourceQuery, SystemPort, Tag, TagPage,
    Target, TargetPage, TargetPort, TargetQuery, Task, TaskAction, TaskPage, TaskPort, TaskQuery,
    Ticket, TicketPage, Timezone, TlsCertificatePage, User, UserPage, UserSetting, UserSettingList,
    UserSettingQuery,
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
        filters::{get_filter, get_filters, GetFiltersOpts},
        groups::{
            create_group, delete_group, get_group, get_groups, modify_group, GetGroupsOpts,
            GroupOpts,
        },
        hosts::{get_host, get_hosts, GetHostsOpts},
        notes::{create_note, delete_note, get_notes, modify_note, GetNotesOpts, NoteOpts},
        nvts::{get_nvt, get_nvt_families, get_nvts, GetNvtsOpts},
        overrides::{
            create_override, delete_override, get_overrides, modify_override, GetOverridesOpts,
            OverrideOpts,
        },
        permissions::{
            create_permission, delete_permission, get_permission, get_permissions,
            modify_permission, GetPermissionsOpts, PermissionOpts,
        },
        port_lists::{
            create_port_list, delete_port_list, get_port_list, get_port_lists, modify_port_list,
            GetPortListsOpts, PortListOpts,
        },
        report_formats::{get_report_format, get_report_formats, GetReportFormatsOpts},
        reports::{delete_report, get_reports, GetReportsOpts},
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
        tags::{get_tag, get_tags, GetTagsOpts},
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
        tickets::{get_ticket, get_tickets, GetTicketsOpts},
        user_settings::{
            get_user_setting, get_user_settings, modify_user_setting, GetUserSettingsOpts,
            ModifyUserSettingOpts,
        },
        users::{
            create_user, delete_user, get_user, get_users, modify_user, GetUsersOpts,
            UserHostAccess, UserOpts,
        },
    },
    responses::{
        ActionResponse, AuthenticateResponse, CreateAlertResponse, CreateCredentialResponse,
        CreateGroupResponse, CreateNoteResponse, CreateOverrideResponse, CreatePermissionResponse,
        CreatePortListResponse, CreateRoleResponse, CreateScanConfigResponse,
        CreateScheduleResponse, CreateTargetResponse, CreateTaskResponse, CreateUserResponse,
        GetAlertsResponse, GetCredentialsResponse, GetFeedsResponse, GetFiltersResponse,
        GetGroupsResponse, GetHostsResponse, GetNotesResponse, GetNvtFamiliesResponse,
        GetNvtsResponse, GetOverridesResponse, GetPermissionsResponse, GetPortListsResponse,
        GetReportFormatsResponse, GetReportsResponse, GetResultsResponse, GetRolesResponse,
        GetScanConfigsResponse, GetScannersResponse, GetSchedulesResponse, GetTagsResponse,
        GetTargetsResponse, GetTasksResponse, GetTicketsResponse, GetUserSettingsResponse,
        GetUsersResponse, GetVersionResponse, ModifyUserSettingResponse, ResumeTaskResponse,
        StartTaskResponse, User as GmpUser,
    },
    EntityId, FilterFragmentError, PaginatedFilter, Pagination as GmpPagination,
};
use gvm_protocol::{Request, Response};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tracing::{field, info_span, Instrument};

use crate::conversions::{
    alert_from_gmp, credential_from_gmp, feed_from_gmp, filter_from_gmp, group_from_gmp,
    host_from_gmp, map_gvm_error, map_parse_error, note_from_gmp, nvt_family_from_gmp,
    nvt_from_gmp, override_from_gmp, parse_alert_condition, parse_alert_event, parse_alert_method,
    parse_alive_test, parse_credential_type, parse_entity_id, parse_hosts_ordering,
    parse_permission_subject_type, parse_snmp_auth_algorithm, parse_snmp_privacy_algorithm,
    parse_user_auth_type, permission_from_gmp, port_list_from_gmp, report_format_from_gmp,
    report_from_gmp, result_from_gmp, result_from_report_closed_cve, result_from_report_error,
    result_from_report_vulnerability, role_from_gmp, scan_config_from_gmp, scanner_from_gmp,
    schedule_from_gmp, tag_from_gmp, target_from_gmp, task_from_gmp, ticket_from_gmp,
    tls_certificate_from_report_tls_certificate, user_from_gmp, user_setting_from_gmp,
};

const MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING: usize = 64;

struct SessionClient {
    client: AsyncMutex<GmpClient<UnixSocketConnection>>,
    command_slots: Arc<Semaphore>,
}

impl SessionClient {
    fn new(client: GmpClient<UnixSocketConnection>) -> Self {
        Self {
            client: AsyncMutex::new(client),
            command_slots: Arc::new(Semaphore::new(MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING)),
        }
    }

    async fn lock(&self) -> Result<SessionClientGuard<'_>, GatewayError> {
        let slot = Arc::clone(&self.command_slots)
            .try_acquire_owned()
            .map_err(|_| {
                GatewayError::TooManyRequests("session command queue saturated".to_string())
            })?;
        let guard = self.client.lock().await;
        Ok(SessionClientGuard { _slot: slot, guard })
    }
}

struct SessionClientGuard<'a> {
    _slot: OwnedSemaphorePermit,
    guard: tokio::sync::MutexGuard<'a, GmpClient<UnixSocketConnection>>,
}

impl Deref for SessionClientGuard<'_> {
    type Target = GmpClient<UnixSocketConnection>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for SessionClientGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

type SharedClient = Arc<SessionClient>;

/// gvmd adapter backed by session-keyed GMP clients.
#[derive(Clone)]
pub struct GvmdAdapter {
    socket_path: PathBuf,
    sessions: Arc<Mutex<HashMap<SessionTokenDigest, SharedClient>>>,
}

impl fmt::Debug for GvmdAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_count = self.sessions.lock().map(|guard| guard.len()).ok();
        formatter
            .debug_struct("GvmdAdapter")
            .field("socket_path", &self.socket_path)
            .field("session_count", &session_count)
            .finish()
    }
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
            let response = client
                .call(authenticate(username, password))
                .await
                .map_err(map_gvm_error)?;
            AuthenticateResponse::from_response(&response).map_err(map_parse_error)?;

            self.sessions
                .lock()
                .map_err(|_| {
                    GatewayError::BackendUnavailable("session store unavailable".to_string())
                })?
                .insert(
                    SessionTokenDigest::from_token(session_token),
                    Arc::new(SessionClient::new(client)),
                );

            Ok(())
        }
        .instrument(span)
        .await
    }

    fn session_client(&self, session_token: &str) -> Result<SharedClient, GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .get(&SessionTokenDigest::from_token(session_token))
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
                .await?
                .call(request)
                .await
                .map_err(map_gvm_error)?;
            tracing::Span::current().record("gvmd_status", field::display("ok"));
            Ok(response)
        }
        .instrument(span)
        .await
    }

    async fn get_gmp_user(&self, session_token: &str, id: &str) -> Result<GmpUser, GatewayError> {
        let response = self
            .call_with_session(session_token, "users.get", get_user(&parse_entity_id(id)?))
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("user {id} not found")))
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

    async fn saved_filter_term(
        &self,
        session_token: &str,
        filter_id: Option<&EntityId>,
    ) -> Result<Option<String>, GatewayError> {
        let Some(filter_id) = filter_id else {
            return Ok(None);
        };

        let response = self
            .call_with_session(session_token, "filters.get", get_filter(filter_id))
            .await?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("filter {filter_id} not found")))
            .map(|filter| filter.term)
    }

    async fn paginated_filter_resolving_filter_id(
        &self,
        session_token: &str,
        prefix: Option<&str>,
        filter_string: Option<&str>,
        filter_id: Option<&EntityId>,
        page: u32,
        per_page: u32,
        reserved_terms: &[&str],
    ) -> Result<Option<String>, GatewayError> {
        let saved_filter = self.saved_filter_term(session_token, filter_id).await?;
        composed_filter(
            prefix,
            saved_filter.as_deref(),
            filter_string,
            Some(GmpPagination::new(page as usize, per_page as usize)),
            reserved_terms,
        )
    }

    async fn filter_resolving_filter_id(
        &self,
        session_token: &str,
        prefix: Option<&str>,
        filter_string: Option<&str>,
        filter_id: Option<&EntityId>,
        reserved_terms: &[&str],
    ) -> Result<Option<String>, GatewayError> {
        let saved_filter = self.saved_filter_term(session_token, filter_id).await?;
        composed_filter(
            prefix,
            saved_filter.as_deref(),
            filter_string,
            None,
            reserved_terms,
        )
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

fn gvmd_total(filtered: Option<u32>, total: Option<u32>, current_len: usize) -> u32 {
    filtered.or(total).unwrap_or(current_len as u32)
}

fn paged_slice<T>(items: Vec<T>, page: u32, per_page: u32) -> Vec<T> {
    let start = ((page.saturating_sub(1)) * per_page) as usize;
    items
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect()
}

fn needs_client_side_pagination_fallback<T>(items: &[T], total: u32, page: u32) -> bool {
    page > 1 && items.is_empty() && total == 0
}

fn backend_ignored_pagination<T>(items: &[T], per_page: u32) -> bool {
    items.len() > per_page as usize
}

fn paginated_filter(
    prefix: Option<&str>,
    filter_string: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<Option<String>, GatewayError> {
    paginated_filter_with_reserved_terms(prefix, filter_string, page, per_page, &[])
}

fn paginated_filter_with_reserved_terms(
    prefix: Option<&str>,
    filter_string: Option<&str>,
    page: u32,
    per_page: u32,
    reserved_terms: &[&str],
) -> Result<Option<String>, GatewayError> {
    let mut filter = PaginatedFilter::new();
    if let Some(prefix) = prefix {
        filter = filter.with_clause(prefix);
    }
    filter = filter
        .try_with_filter_string(filter_string, reserved_terms)
        .map_err(map_filter_fragment_error)?;
    Ok(filter
        .with_pagination(GmpPagination::new(page as usize, per_page as usize))
        .build())
}

fn composed_filter(
    prefix: Option<&str>,
    saved_filter_string: Option<&str>,
    filter_string: Option<&str>,
    pagination: Option<GmpPagination>,
    reserved_terms: &[&str],
) -> Result<Option<String>, GatewayError> {
    let mut filter = PaginatedFilter::new();
    filter = filter.with_filter_string(saved_filter_string);
    if let Some(prefix) = prefix {
        filter = filter.with_clause(prefix);
    }
    filter = filter
        .try_with_filter_string(filter_string, reserved_terms)
        .map_err(map_filter_fragment_error)?;
    if let Some(pagination) = pagination {
        filter = filter.with_pagination(pagination);
    }
    Ok(filter.build())
}

fn map_filter_fragment_error(error: FilterFragmentError) -> GatewayError {
    match error {
        FilterFragmentError::ReservedTerm { term } => {
            GatewayError::InvalidInput(format!("filter contains reserved term '{term}'"))
        }
    }
}

fn note_opts_from_create_input(input: CreateNoteInput) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

fn note_opts_from_modify_input(input: ModifyNoteInput) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

fn override_opts_from_create_input(
    input: CreateOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
}

fn override_opts_from_modify_input(
    input: ModifyOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_alerts(GetAlertsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetAlertsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(alert_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(AlertPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_alert(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_alert(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_schedules(GetSchedulesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                tasks: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetSchedulesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(schedule_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(SchedulePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_schedule(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_schedule(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_credentials(GetCredentialsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetCredentialsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(credential_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(CredentialPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_credential(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_credential(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_port_lists(GetPortListsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPortListsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(port_list_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(PortListPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_port_list(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_port_list(&parse_entity_id(id)?, ultimate))
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
            .await?
            .call(get_feeds())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFeedsResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.items.into_iter().map(feed_from_gmp).collect())
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
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetUsersResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(user_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(UserPage {
            data: items,
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
                        host_access: input.hosts.map(UserHostAccess::allow),
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
        Ok(user_from_gmp(self.get_gmp_user(session_token, id).await?))
    }

    async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        let user_id = parse_entity_id(id)?;
        let ModifyUserInput {
            comment,
            password,
            hosts,
            role_ids,
            authentication_type,
        } = input;
        let host_access = match hosts {
            Some(hosts) => Some(UserHostAccess::allow(hosts)),
            None => self.get_gmp_user(session_token, id).await?.host_access(),
        };
        let role_ids = role_ids
            .unwrap_or_default()
            .into_iter()
            .map(|value| parse_entity_id(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_type = authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let response = self
            .call_with_session(
                session_token,
                "users.modify",
                modify_user(
                    &user_id,
                    UserOpts {
                        comment,
                        password,
                        host_access,
                        role_ids,
                        auth_type,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_user(session_token, id).await
    }

    async fn delete_user(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "users.delete",
                delete_user(&parse_entity_id(id)?, ultimate),
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
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(group_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(GroupPage {
            data: items,
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_group(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_roles(GetRolesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetRolesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(role_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(RolePage {
            data: items,
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_role(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_role(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_permissions(GetPermissionsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetPermissionsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(permission_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(PermissionPage {
            data: items,
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_permission(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_permission(&parse_entity_id(id)?, ultimate))
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
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter = self
            .filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_user_settings(GetUserSettingsOpts {
                filter,
                filter_id: None,
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
            .await?
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
            .await?
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
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
        let parsed = GetTargetsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(target_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        // Compatibility for backends/mocks that accept pagination terms but do
        // not report totals for later pages; preserve the REST page contract.
        if needs_client_side_pagination_fallback(&items, total, query.page) {
            let fallback = self
                .call_with_session(
                    session_token,
                    "targets.list",
                    get_targets(GetTargetsOpts {
                        filter_string: self
                            .filter_resolving_filter_id(
                                session_token,
                                None,
                                query.filter_string.as_deref(),
                                filter_id.as_ref(),
                                &[],
                            )
                            .await?,
                        filter_id: None,
                        trash: None,
                        details: Some(true),
                    }),
                )
                .await?;
            let parsed = GetTargetsResponse::from_response(&fallback).map_err(map_parse_error)?;
            let items = parsed
                .items
                .into_iter()
                .map(target_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

            return Ok(TargetPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(TargetPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
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
                        ssh_credential_id: input
                            .ssh_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        smb_credential_id: input
                            .smb_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        esxi_credential_id: input
                            .esxi_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        snmp_credential_id: input
                            .snmp_credential_id
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
                        reverse_lookup_only: None,
                        reverse_lookup_unify: None,
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
                        ssh_credential_id: input
                            .ssh_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        smb_credential_id: input
                            .smb_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        esxi_credential_id: input
                            .esxi_credential_id
                            .as_deref()
                            .map(parse_entity_id)
                            .transpose()?,
                        snmp_credential_id: input
                            .snmp_credential_id
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

    async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "targets.delete",
                delete_target(&parse_entity_id(id)?, ultimate),
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
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    schedules_only: None,
                    ignore_pagination: None,
                }),
            )
            .await?;
        let parsed = GetTasksResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(task_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(TaskPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
                        preferences: input.preferences,
                    },
                ),
            )
            .await?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_task(session_token, id).await
    }

    async fn delete_task(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "tasks.delete",
                delete_task_cmd(&parse_entity_id(id)?, ultimate),
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
        let parsed = ResumeTaskResponse::from_response(&response).map_err(map_parse_error)?;
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_reports(GetReportsOpts {
                report_id: None,
                filter_string,
                filter_id: None,
                details: Some(false),
                ignore_pagination: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(report_from_gmp)
            .collect::<Vec<_>>();

        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ReportPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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

        // Fetch only report metadata; embedded results are loaded below through
        // the explicit result-window request.
        let response = client
            .lock()
            .await?
            .call(get_reports(GetReportsOpts {
                report_id: Some(report_id),
                filter_string: None,
                filter_id: None,
                details: Some(false),
                ignore_pagination: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut report = parsed
            .items
            .into_iter()
            .next()
            .map(report_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("report {id} not found")))?;

        // Fetch the explicitly requested embedded-result window for this report.
        let filter = if opts.ignore_pagination {
            Some(format!("report_id={id}"))
        } else {
            paginated_filter(
                Some(&format!("report_id={id}")),
                None,
                opts.page,
                opts.per_page,
            )?
        };

        let results_response = client
            .lock()
            .await?
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
            .await?
            .get_report_export(&report_id, &report_format_id)
            .await
            .map_err(map_gvm_error)?;

        Ok(ReportExport {
            bytes: export.bytes,
            content_type: export.content_type,
            extension: export.extension,
        })
    }

    async fn delete_report(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_report(&parse_entity_id(id)?, ultimate))
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

        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter = self
            .paginated_filter_resolving_filter_id(
                session_token,
                Some(&format!("report_id={report_id}")),
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &["report_id"],
            )
            .await?;

        let response = client
            .lock()
            .await?
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

        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_vulnerabilities(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_vulns(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_vulns") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_vulns",
                    "report vulnerabilities",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let items = parsed
            .items
            .into_iter()
            .map(result_from_report_vulnerability)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_tls_certificates(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<TlsCertificatePage, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_tls_certificates(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error)
                if typed_report_detail_unsupported(&error, "get_report_tls_certificates") =>
            {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_tls_certificates",
                    "report TLS certificates",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let certificates = parsed
            .items
            .into_iter()
            .map(tls_certificate_from_report_tls_certificate)
            .collect::<Vec<_>>();
        let total = gvmd_total(
            parsed.counts.filtered,
            parsed.counts.total,
            certificates.len(),
        );

        Ok(TlsCertificatePage {
            data: certificates,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_errors(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_errors(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_errors") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_errors",
                    "report errors",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let items = parsed
            .items
            .into_iter()
            .map(result_from_report_error)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_closed_cves(
        &self,
        session_token: &str,
        report_id: &str,
        query: &ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let report_id = parse_entity_id(report_id)?;
        let opts = report_detail_query(self, session_token, query).await?;
        let parsed = match client
            .lock()
            .await?
            .get_report_closed_cves(&report_id, opts)
            .await
        {
            Ok(parsed) => parsed,
            Err(error) if typed_report_detail_unsupported(&error, "get_report_closed_cves") => {
                return Err(unsupported_typed_report_detail_error(
                    "get_report_closed_cves",
                    "report closed CVEs",
                ));
            }
            Err(error) => return Err(map_gvm_error(error)),
        };
        let items = parsed
            .items
            .into_iter()
            .map(result_from_report_closed_cve)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }
}

async fn report_detail_query(
    adapter: &GvmdAdapter,
    session_token: &str,
    query: &ResultQuery,
) -> Result<GetReportDetailsOpts, GatewayError> {
    let filter_id = query
        .filter_id
        .as_deref()
        .map(parse_entity_id)
        .transpose()?;
    Ok(GetReportDetailsOpts {
        filter_string: adapter
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &["report_id"],
            )
            .await?,
        filter_id: None,
        ignore_pagination: None,
        details: Some(true),
    })
}

fn typed_report_detail_unsupported(error: &gvm_client::GvmError, command: &str) -> bool {
    matches!(
        error,
        gvm_client::GvmError::UnsupportedCommand { command: unsupported, .. }
            if unsupported == command
    )
}

// The gateway translates between REST/gRPC and GMP, but it does not emulate
// GMP functionality that the connected gvmd does not implement yet.
fn unsupported_typed_report_detail_error(command: &str, resource: &str) -> GatewayError {
    GatewayError::NotImplemented(format!(
        "{resource} are not available because gvmd does not implement `{command}` on this backend version; the proxy does not emulate unsupported GMP commands"
    ))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_results(GetResultsOpts {
                filter_string,
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

        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ResultPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_result(&self, session_token: &str, id: &str) -> Result<ScanResult, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_scan_configs(GetScanConfigsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScanConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
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
            .await?
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
            .await?
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
            .await?
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

    async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_scan_config(&parse_entity_id(id)?, ultimate))
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
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_scanners(GetScannersOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScannersResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scanner_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScannerPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_scanner(&self, session_token: &str, id: &str) -> Result<Scanner, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
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
impl SupportingResourcePort for GvmdAdapter {
    async fn list_hosts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_hosts(GetHostsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetHostsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(host_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.meta
                .name
                .cmp(&right.meta.name)
                .then_with(|| left.ip.cmp(&right.ip))
                .then_with(|| left.meta.id.cmp(&right.meta.id))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(HostPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_host(&self, session_token: &str, id: &str) -> Result<Host, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_host(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetHostsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(host_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("host {id} not found")))
    }

    async fn list_report_formats(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_report_formats(GetReportFormatsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportFormatsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(report_format_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(ReportFormatPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_report_format(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ReportFormat, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_report_format(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetReportFormatsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(report_format_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("report format {id} not found")))
    }

    async fn list_filters(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_filters(GetFiltersOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(filter_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(FilterPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_filter(&self, session_token: &str, id: &str) -> Result<Filter, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_filter(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFiltersResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(filter_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("filter {id} not found")))
    }

    async fn list_tags(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_tags(GetTagsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTagsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(tag_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(TagPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_tag(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTagsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(tag_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("tag {id} not found")))
    }

    async fn list_tickets(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_tickets(GetTicketsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTicketsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(ticket_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(TicketPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_ticket(&self, session_token: &str, id: &str) -> Result<Ticket, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_ticket(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTicketsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(ticket_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("ticket {id} not found")))
    }

    async fn list_notes(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_notes(GetNotesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNotesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(note_from_gmp).collect();
        Ok(NotePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_note(&self, session_token: &str, id: &str) -> Result<Note, GatewayError> {
        let client = self.session_client(session_token)?;
        let note_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", note_id.as_str());
        let response = client
            .lock()
            .await?
            .call(get_notes(GetNotesOpts {
                filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNotesResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .find(|note| note.meta.id.as_str() == note_id.as_str())
            .map(note_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("note {id} not found")))
    }

    async fn create_note(
        &self,
        session_token: &str,
        input: CreateNoteInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let nvt_oid = input.nvt_oid.clone();
        let opts = note_opts_from_create_input(input)?;
        let response = client
            .lock()
            .await?
            .call(create_note(&nvt_oid, opts))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateNoteResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_note(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        let client = self.session_client(session_token)?;
        let note_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_note(&note_id, note_opts_from_modify_input(input)?))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_note(session_token, id).await
    }

    async fn delete_note(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_note(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_overrides(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_overrides(GetOverridesOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetOverridesResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed.items;
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        let data = items.into_iter().map(override_from_gmp).collect();
        Ok(OverridePage {
            data,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_override(&self, session_token: &str, id: &str) -> Result<Override, GatewayError> {
        let client = self.session_client(session_token)?;
        let override_id = parse_entity_id(id)?;
        let uuid_filter = format!("uuid={}", override_id.as_str());
        let response = client
            .lock()
            .await?
            .call(get_overrides(GetOverridesOpts {
                filter_string: paginated_filter(Some(&uuid_filter), None, 1, 1)?,
                filter_id: None,
                trash: None,
                details: Some(true),
                result: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetOverridesResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .find(|override_| override_.meta.id.as_str() == override_id.as_str())
            .map(override_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("override {id} not found")))
    }

    async fn create_override(
        &self,
        session_token: &str,
        input: CreateOverrideInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let nvt_oid = input.nvt_oid.clone();
        let opts = override_opts_from_create_input(input)?;
        let response = client
            .lock()
            .await?
            .call(create_override(&nvt_oid, opts))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateOverrideResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_override(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        let client = self.session_client(session_token)?;
        let override_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_override(
                &override_id,
                override_opts_from_modify_input(input)?,
            ))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_override(session_token, id).await
    }

    async fn delete_override(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_override(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_nvts(
        &self,
        session_token: &str,
        query: &SupportingResourceQuery,
    ) -> Result<NvtPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let response = client
            .lock()
            .await?
            .call(get_nvts(GetNvtsOpts {
                filter_string,
                filter_id: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(nvt_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.oid
                .cmp(&right.oid)
                .then_with(|| left.name.cmp(&right.name))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        if needs_client_side_pagination_fallback(&items, total, query.page)
            || backend_ignored_pagination(&items, query.per_page)
        {
            let fallback = self
                .call_with_session(
                    session_token,
                    "nvts.list",
                    get_nvts(GetNvtsOpts {
                        filter_string: self
                            .filter_resolving_filter_id(
                                session_token,
                                None,
                                query.filter_string.as_deref(),
                                filter_id.as_ref(),
                                &[],
                            )
                            .await?,
                        filter_id: None,
                        details: Some(true),
                    }),
                )
                .await?;
            let parsed = GetNvtsResponse::from_response(&fallback).map_err(map_parse_error)?;
            let mut items = parsed
                .items
                .into_iter()
                .map(nvt_from_gmp)
                .collect::<Vec<_>>();
            items.sort_by(|left, right| {
                left.oid
                    .cmp(&right.oid)
                    .then_with(|| left.name.cmp(&right.name))
            });
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

            return Ok(NvtPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(NvtPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_nvt(&self, session_token: &str, oid: &str) -> Result<Nvt, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_nvt(oid))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(nvt_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("nvt {oid} not found")))
    }

    async fn list_nvt_families(
        &self,
        session_token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<NvtFamilyPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_nvt_families())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtFamiliesResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(nvt_family_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = parsed.counts.total.unwrap_or(items.len() as u32);
        Ok(NvtFamilyPage {
            data: paged_slice(items, page, per_page),
            pagination: paged_pagination(total, page, per_page),
        })
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

    async fn disconnect_session(&self, session: &SessionTokenDigest) -> Result<(), GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .remove(session);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        io::Write,
        sync::{Arc, Mutex, OnceLock},
        time::Duration,
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
    fn safe_session_id_uses_documented_token_suffix() {
        let token = "gvm_sess_1234567890abcdef";

        let session_id = safe_session_id(token);

        assert_eq!(session_id, "session:90abcdef");
        assert!(!session_id.contains(token));
    }

    #[test]
    fn gvmd_adapter_session_client_fails_without_session() {
        let adapter = GvmdAdapter::unix_socket("/tmp/nonexistent.sock");
        let result = adapter.session_client("missing-token");
        assert!(matches!(result, Err(GatewayError::SessionInvalidated(_))));
    }

    #[test]
    fn paginated_filter_appends_backend_paging_terms() {
        // GMP filter paging is one-based: page 3 with 25 rows starts at item 51.
        assert_eq!(
            paginated_filter(Some("report_id=abc"), Some("severity>5"), 3, 25),
            Ok(Some(
                "report_id=abc severity>5 first=51 rows=25".to_string()
            ))
        );
        assert_eq!(
            paginated_filter(None, Some("   "), 1, 10),
            Ok(Some("first=1 rows=10".to_string()))
        );
    }

    #[test]
    fn paginated_filter_rejects_caller_pagination_terms() {
        // User filter fragments must not override backend pagination terms that
        // the gateway appends after validation.
        let result = paginated_filter(None, Some("severity>5 first=1"), 3, 25);

        assert!(matches!(
            result,
            Err(GatewayError::InvalidInput(detail))
                if detail == "filter contains reserved term 'first'"
        ));
    }

    #[test]
    fn paginated_filter_rejects_endpoint_owned_scope_terms() {
        // Report-scoped endpoints add report_id themselves, so a caller filter
        // may not inject another report_id clause.
        let result = paginated_filter_with_reserved_terms(
            Some("report_id=abc"),
            Some("report_id=def severity>5"),
            1,
            25,
            &["report_id"],
        );

        assert!(matches!(
            result,
            Err(GatewayError::InvalidInput(detail))
                if detail == "filter contains reserved term 'report_id'"
        ));
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

        async fn create_mock_adapter_v22_8() -> (GvmdAdapter, MockGmpServer, String) {
            let report_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid report id");
            let filter_id = uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("valid filter id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_8)
                .seed(move |store| {
                    store.create(Resource::with_id("report", "Typed report", report_id));
                    let mut filter = Resource::with_id("filter", "Saved alarm filter", filter_id);
                    filter.set_attr("term", "threat=Alarm");
                    store.create(filter);
                })
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

        fn assert_paginated_commands(
            server: &MockGmpServer,
            command_name: &str,
            expected_filter: &str,
            expected_count: usize,
        ) {
            let matching_commands = server
                .command_history()
                .into_iter()
                .filter(|record| record.command_name() == command_name)
                .collect::<Vec<_>>();

            assert_eq!(
                matching_commands.len(),
                expected_count,
                "{command_name} should be called {expected_count} time(s) for this paginated list request"
            );
            let first_xml = String::from_utf8(matching_commands[0].raw_xml().to_vec())
                .expect("xml command should be UTF-8");
            assert!(
                first_xml.contains(expected_filter),
                "{command_name} should include backend pagination filter {expected_filter:?}; xml={first_xml}"
            );
        }

        macro_rules! assert_backend_pagination {
            ($adapter:expr, $server:expr, $call:expr, $command_name:literal, $expected_filter:literal) => {{
                $server.clear_history();

                let result = $call.await;
                assert!(
                    result.is_ok(),
                    "{} should accept the paginated query: {:?}",
                    $command_name,
                    result
                );
                assert_paginated_commands(&$server, $command_name, $expected_filter, 1);
            }};
            ($adapter:expr, $server:expr, $call:expr, $command_name:literal, $expected_filter:literal, $expected_count:literal) => {{
                $server.clear_history();

                let result = $call.await;
                assert!(
                    result.is_ok(),
                    "{} should accept the paginated query: {:?}",
                    $command_name,
                    result
                );
                assert_paginated_commands(
                    &$server,
                    $command_name,
                    $expected_filter,
                    $expected_count,
                );
            }};
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
            let token = "gvm_sess_adapter_debug_secret";
            let result = adapter.connect_session(token, "admin", "admin").await;

            assert!(result.is_ok());
            let debug = format!("{adapter:?}");
            assert!(debug.contains("session_count"));
            assert!(!debug.contains(token));
            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_connect_session_auth_failure_returns_unauthorized() {
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .unix_socket_auto()
                .build()
                .await
                .unwrap();

            let adapter = GvmdAdapter::unix_socket(server.socket_path().unwrap());
            let result = adapter.connect_session("token", "admin", "wrong").await;

            assert!(matches!(result, Err(GatewayError::Unauthorized(_))));
            let session_digest = SessionTokenDigest::from_token("token");
            let disconnect_result = adapter.disconnect_session(&session_digest).await;
            assert!(disconnect_result.is_ok());
            let follow_up = adapter
                .list_targets(
                    "token",
                    &TargetQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;
            assert!(matches!(
                follow_up,
                Err(GatewayError::SessionInvalidated(_))
            ));

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
                ssh_credential_id: None,
                smb_credential_id: None,
                esxi_credential_id: None,
                snmp_credential_id: None,
            };
            let result = adapter.modify_target(&token, &id, modify_input).await;

            assert!(result.is_ok());
            let target = result.unwrap();
            assert_eq!(target.name, "After Modify");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_modify_task_forwards_preferences() {
            let (adapter, server, token) = create_mock_adapter().await;
            server.clear_history();

            // Regression coverage for issue #228: task preferences supplied on
            // modify must reach the typed rust-gvm command instead of being
            // dropped by the gvmd adapter.
            let result = adapter
                .modify_task(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440010",
                    ModifyTaskInput {
                        preferences: vec![("scanner.max_hosts".to_string(), "64".to_string())],
                        ..Default::default()
                    },
                )
                .await;

            assert!(
                result.is_err(),
                "mock backend may reject the unknown task, but the command should still be emitted"
            );
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "modify_task")
                .expect("modify_task command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("<scanner_name>scanner.max_hosts</scanner_name>"));
            assert!(xml.contains("<value>64</value>"));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_modify_user_preserves_hosts_when_request_omits_hosts() {
            let user_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099")
                .expect("valid user id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .seed(move |store| {
                    let mut user = Resource::with_id("user", "restricted-user", user_id);
                    user.set_attr("hosts_allow", "1");
                    user.set_attr("hosts", "192.0.2.0/24");
                    store.create(user);
                })
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
            server.clear_history();

            // Regression coverage for #274: gvmd treats an absent <hosts>
            // element on modify_user as "allow all", so unrelated updates must
            // echo the current host restriction through the typed rust-gvm
            // command when the request did not explicitly change hosts.
            let result = adapter
                .modify_user(
                    token,
                    &user_id.to_string(),
                    ModifyUserInput {
                        comment: Some("updated comment".to_string()),
                        ..Default::default()
                    },
                )
                .await;

            assert!(result.is_ok(), "modify_user should succeed: {result:?}");
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "modify_user")
                .expect("modify_user command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("<comment>updated comment</comment>"));
            assert!(
                xml.contains("<hosts allow=\"1\">192.0.2.0/24</hosts>"),
                "modify_user should preserve existing host restrictions; xml={xml}"
            );

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_modify_user_preserves_deny_hosts_when_request_omits_hosts() {
            let user_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440100")
                .expect("valid user id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .seed(move |store| {
                    let mut user = Resource::with_id("user", "restricted-user", user_id);
                    user.set_attr("hosts_allow", "0");
                    user.set_attr("hosts", "198.51.100.0/24");
                    store.create(user);
                })
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
            server.clear_history();

            // Regression coverage for #274: preserving only the host string is
            // not enough. Deny-mode restrictions must keep allow="0" when an
            // unrelated user update omits hosts.
            let result = adapter
                .modify_user(
                    token,
                    &user_id.to_string(),
                    ModifyUserInput {
                        comment: Some("updated comment".to_string()),
                        ..Default::default()
                    },
                )
                .await;

            assert!(result.is_ok(), "modify_user should succeed: {result:?}");
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "modify_user")
                .expect("modify_user command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("<comment>updated comment</comment>"));
            assert!(
                xml.contains("<hosts allow=\"0\">198.51.100.0/24</hosts>"),
                "modify_user should preserve deny-mode host restrictions; xml={xml}"
            );

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
            let result = adapter.delete_target(&token, &id, false).await;

            assert!(result.is_ok());

            // Verify it's gone
            let get_result = adapter.get_target(&token, &id).await;
            assert!(matches!(get_result, Err(GatewayError::NotFound(_))));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_direct_lists_emit_backend_pagination_filter() {
            let (adapter, server, token) = create_mock_adapter().await;

            // Regression coverage for issue #210: directly backed gvmd
            // collections must push REST pagination through GMP filters instead
            // of fetching full collections and slicing locally.
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_alerts(
                    &token,
                    &AlertQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_alerts",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_schedules(
                    &token,
                    &ScheduleQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_schedules",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_credentials(
                    &token,
                    &CredentialQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_credentials",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_port_lists(
                    &token,
                    &PortListQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_port_lists",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_users(
                    &token,
                    &IdentityQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_users",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_groups(
                    &token,
                    &IdentityQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_groups",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_roles(
                    &token,
                    &IdentityQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_roles",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_permissions(
                    &token,
                    &IdentityQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_permissions",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_targets(
                    &token,
                    &TargetQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_targets",
                "filter=\"name~Target first=11 rows=10\"",
                2
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_tasks(
                    &token,
                    &TaskQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_tasks",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_reports(
                    &token,
                    &ReportQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_reports",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_results(
                    &token,
                    &ResultQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_results",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.get_report_results(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_results",
                "filter=\"report_id=550e8400-e29b-41d4-a716-446655440000 name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_scan_configs(
                    &token,
                    &ScanConfigQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_configs",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_scanners(
                    &token,
                    &ScannerQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_scanners",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_report_formats(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_report_formats",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_filters(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_filters",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_tags(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_tags",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_tickets(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_tickets",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_notes(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_notes",
                "filter=\"name~Target first=11 rows=10\""
            );
            assert_backend_pagination!(
                adapter,
                server,
                adapter.list_overrides(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~Target".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    }
                ),
                "get_overrides",
                "filter=\"name~Target first=11 rows=10\""
            );

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_targets_resolves_filter_id_before_paginating() {
            let filter_id = uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("valid filter id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .seed(move |store| {
                    let mut filter = Resource::with_id("filter", "Saved target filter", filter_id);
                    filter.set_attr("term", "name~Saved");
                    store.create(filter);
                })
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
            server.clear_history();

            // Regression coverage for issue #272: real gvmd ignores the
            // inline filter when filter_id is set, so pagination must be
            // composed into the inline filter after resolving the saved term.
            let result = adapter
                .list_targets(
                    token,
                    &TargetQuery {
                        filter_string: Some("comment~web".to_string()),
                        filter_id: Some(filter_id.to_string()),
                        page: 2,
                        per_page: 10,
                    },
                )
                .await;

            assert!(result.is_ok(), "target list should succeed: {result:?}");
            let history = server.command_history();
            let target_command = history
                .iter()
                .find(|record| record.command_name() == "get_targets")
                .expect("get_targets command should be recorded");
            let xml = String::from_utf8(target_command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("filter=\"name~Saved comment~web first=11 rows=10\""));
            assert!(!xml.contains("filter_id"));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_alerts_filter_id_resolution_does_not_deadlock() {
            let filter_id = uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("valid filter id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_7)
                .seed(move |store| {
                    let mut filter = Resource::with_id("filter", "Saved alert filter", filter_id);
                    filter.set_attr("term", "name~Saved");
                    store.create(filter);
                })
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
            server.clear_history();

            // Regression coverage for the direct-lock list paths: resolving a
            // saved filter must happen before the session client is locked, or
            // the nested get_filter request waits forever on the same mutex.
            let result = tokio::time::timeout(
                Duration::from_millis(250),
                adapter.list_alerts(
                    token,
                    &AlertQuery {
                        filter_string: Some("comment~web".to_string()),
                        filter_id: Some(filter_id.to_string()),
                        page: 2,
                        per_page: 10,
                    },
                ),
            )
            .await;

            let history = server.command_history();
            server.shutdown().await;

            let page = result
                .expect("list_alerts with filterId should not deadlock")
                .expect("list_alerts with filterId should succeed");
            assert_eq!(page.pagination.page, 2);
            assert_eq!(page.pagination.per_page, 10);

            let alert_command = history
                .iter()
                .find(|record| record.command_name() == "get_alerts")
                .expect("get_alerts command should be recorded");
            let xml = String::from_utf8(alert_command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("filter=\"name~Saved comment~web first=11 rows=10\""));
            assert!(!xml.contains("filter_id"));
        }

        #[tokio::test]
        async fn gvmd_adapter_list_reports_requests_summary_metadata_only() {
            let (adapter, server, token) = create_mock_adapter().await;
            server.clear_history();

            // Regression coverage for issue #273: report listing maps only
            // report summary metadata, so it must not ask gvmd to embed full
            // report bodies or rely on unsupported report-suppression attrs.
            let result = adapter
                .list_reports(
                    &token,
                    &ReportQuery {
                        filter_string: None,
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await;

            assert!(result.is_ok(), "list reports should succeed: {result:?}");
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_reports")
                .expect("get_reports command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("details=\"0\""), "xml={xml}");
            assert!(!xml.contains("details=\"1\""), "xml={xml}");
            assert!(!xml.contains("no_report"), "xml={xml}");

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_hosts_emits_backend_pagination_filter() {
            let (adapter, server, token) = create_mock_adapter().await;
            server.clear_history();

            let result = adapter
                .list_hosts(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("name~host".to_string()),
                        filter_id: None,
                        page: 2,
                        per_page: 10,
                    },
                )
                .await;

            assert!(result.is_ok());
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_assets")
                .expect("get_assets command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("<get_assets"));
            assert!(xml.contains("asset_type=\"host\""));
            assert!(xml.contains("type=\"host\""));
            assert!(xml.contains("filter=\"name~host first=11 rows=10\""));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_list_nvts_emits_backend_pagination_filter() {
            let (adapter, server, token) = create_mock_adapter().await;
            server.clear_history();

            let result = adapter
                .list_nvts(
                    &token,
                    &SupportingResourceQuery {
                        filter_string: Some("family=Databases".to_string()),
                        filter_id: None,
                        page: 3,
                        per_page: 25,
                    },
                )
                .await;

            assert!(result.is_ok());
            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_nvts")
                .expect("get_nvts command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("<get_nvts"));
            assert!(xml.contains("filter=\"family=Databases first=51 rows=25\""));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_vulnerabilities_uses_typed_command() {
            let (adapter, server, token) = create_mock_adapter_v22_8().await;
            server.clear_history();

            let page = adapter
                .get_report_vulnerabilities(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("severity>5".to_string()),
                        filter_id: Some("123e4567-e89b-12d3-a456-426614174000".to_string()),
                        page: 2,
                        per_page: 10,
                    },
                )
                .await
                .expect("typed report vulnerabilities");

            assert_eq!(page.pagination.page, 2);
            assert_eq!(page.pagination.per_page, 10);
            assert_eq!(page.pagination.total, 1);
            assert_eq!(page.data.len(), 1);
            assert_eq!(page.data[0].host.as_deref(), Some("192.0.2.10"));
            assert_eq!(page.data[0].severity, Some(8.2));
            assert_eq!(
                page.data[0]
                    .nvt
                    .as_ref()
                    .map(|nvt| nvt.cves.clone())
                    .unwrap_or_default(),
                vec!["CVE-2026-0001".to_string()]
            );

            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_report_vulns")
                .expect("get_report_vulns command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""));
            assert!(xml.contains("filter=\"threat=Alarm severity&gt;5 first=11 rows=10\""));
            assert!(!xml.contains("filter_id"));
            assert!(xml.contains("details=\"1\""));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_vulnerabilities_returns_not_implemented_on_v22_7() {
            let (adapter, server, token) = create_mock_adapter().await;
            server.clear_history();

            let error = adapter
                .get_report_vulnerabilities(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("severity>5".to_string()),
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await
                .expect_err("v22.7 should return not implemented");

            assert!(
                matches!(error, GatewayError::NotImplemented(detail) if detail.contains("get_report_vulns"))
            );

            let history = server.command_history();
            assert_eq!(
                history
                    .iter()
                    .filter(|record| record.command_name() == "get_results")
                    .count(),
                0
            );

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_tls_certificates_uses_typed_command() {
            let (adapter, server, token) = create_mock_adapter_v22_8().await;
            server.clear_history();

            let page = adapter
                .get_report_tls_certificates(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("subject~example".to_string()),
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await
                .expect("typed report tls certificates");

            assert_eq!(page.pagination.total, 1);
            assert_eq!(page.data.len(), 1);
            assert_eq!(page.data[0].subject, "CN=example.com");
            assert_eq!(page.data[0].issuer.as_deref(), Some("CN=Example CA"));
            assert_eq!(
                page.data[0].not_after.as_deref(),
                Some("2027-01-01T00:00:00Z")
            );

            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_report_tls_certificates")
                .expect("get_report_tls_certificates command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""));
            assert!(xml.contains("filter=\"subject~example first=1 rows=25\""));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_results_resolves_filter_id_into_inline_filter() {
            let (adapter, server, token) = create_mock_adapter_v22_8().await;
            server.clear_history();

            // Regression coverage for issue #272: gvmd ignores inline filter
            // and pagination attributes when filter_id is set, so the adapter
            // must resolve saved filters and send one composed inline filter.
            let _ = adapter
                .get_report_results(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("severity>5".to_string()),
                        filter_id: Some("123e4567-e89b-12d3-a456-426614174000".to_string()),
                        page: 1,
                        per_page: 25,
                    },
                )
                .await
                .expect("results with filter id");

            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_results")
                .expect("get_results command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains(
                "filter=\"threat=Alarm report_id=550e8400-e29b-41d4-a716-446655440000 severity&gt;5 first=1 rows=25\""
            ));
            assert!(!xml.contains("filter_id"));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_embeds_requested_result_window_larger_than_25() {
            let report_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid report id");
            let server = MockGmpServer::builder()
                .mode(ServerMode::Stateful)
                .version(MockVersion::V22_8)
                .seed(move |store| {
                    store.create(Resource::with_id(
                        "report",
                        "Large embedded report",
                        report_id,
                    ));

                    // Regression coverage for issue #230: the single-report
                    // path must honor the requested embedded-result window
                    // instead of silently forcing the old 25-row window.
                    for index in 0..30 {
                        let result_id = uuid::Uuid::new_v5(&report_id, &[index]);
                        let mut result = Resource::with_id(
                            "result",
                            &format!("Embedded result {index}"),
                            result_id,
                        );
                        result.set_attr("report_id", &report_id.to_string());
                        result.set_attr("first", "1");
                        result.set_attr("rows", "30");
                        result.set_attr("host", "192.0.2.10");
                        result.set_attr("port", "443/tcp");
                        result.set_attr("severity", "5.0");
                        store.create(result);
                    }
                })
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
            server.clear_history();

            let report = adapter
                .get_report(
                    token,
                    &report_id.to_string(),
                    &GetReportOpts {
                        ignore_pagination: false,
                        page: 1,
                        per_page: 30,
                    },
                )
                .await
                .expect("report with embedded result window");

            assert_eq!(report.results.len(), 30);

            let history = server.command_history();
            let report_command = history
                .iter()
                .find(|record| record.command_name() == "get_reports")
                .expect("get_reports command should be recorded");
            let report_xml =
                String::from_utf8(report_command.raw_xml().to_vec()).expect("xml command");
            assert!(
                report_xml.contains("report_id=\"550e8400-e29b-41d4-a716-446655440000\""),
                "xml={report_xml}"
            );
            assert!(report_xml.contains("details=\"0\""), "xml={report_xml}");
            assert!(!report_xml.contains("details=\"1\""), "xml={report_xml}");

            let command = history
                .iter()
                .find(|record| record.command_name() == "get_results")
                .expect("get_results command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("report_id=550e8400-e29b-41d4-a716-446655440000"));
            assert!(xml.contains("first=1 rows=30"));
            assert!(!xml.contains("first=25 rows=25"));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_errors_uses_typed_command() {
            let (adapter, server, token) = create_mock_adapter_v22_8().await;
            server.clear_history();

            let page = adapter
                .get_report_errors(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("threat=Alarm".to_string()),
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await
                .expect("typed report errors");

            assert_eq!(page.pagination.total, 1);
            assert_eq!(page.data.len(), 1);
            assert_eq!(
                page.data[0].description.as_deref(),
                Some("Could not reach host.")
            );
            assert_eq!(page.data[0].threat.as_deref(), Some("Alarm"));
            assert_eq!(
                page.data[0]
                    .nvt
                    .as_ref()
                    .and_then(|nvt| nvt.name.as_deref()),
                Some("Ping Host")
            );

            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_report_errors")
                .expect("get_report_errors command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("filter=\"threat=Alarm first=1 rows=25\""));

            server.shutdown().await;
        }

        #[tokio::test]
        async fn gvmd_adapter_get_report_closed_cves_uses_typed_command() {
            let (adapter, server, token) = create_mock_adapter_v22_8().await;
            server.clear_history();

            let page = adapter
                .get_report_closed_cves(
                    &token,
                    "550e8400-e29b-41d4-a716-446655440000",
                    &ResultQuery {
                        filter_string: Some("severity>4".to_string()),
                        filter_id: None,
                        page: 1,
                        per_page: 25,
                    },
                )
                .await
                .expect("typed report closed cves");

            assert_eq!(page.pagination.total, 1);
            assert_eq!(page.data.len(), 1);
            assert_eq!(page.data[0].name, "CVE-2025-9999");
            assert_eq!(page.data[0].severity, Some(5.0));
            assert_eq!(
                page.data[0]
                    .nvt
                    .as_ref()
                    .map(|nvt| nvt.cves.clone())
                    .unwrap_or_default(),
                vec!["CVE-2025-9999".to_string()]
            );

            let history = server.command_history();
            let command = history
                .iter()
                .find(|record| record.command_name() == "get_report_closed_cves")
                .expect("get_report_closed_cves command should be recorded");
            let xml = String::from_utf8(command.raw_xml().to_vec()).expect("xml command");
            assert!(xml.contains("filter=\"severity&gt;4 first=1 rows=25\""));

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
