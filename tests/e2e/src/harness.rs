// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    env,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use reqwest::{header, Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_TARGET_HOST: &str = "openvasd";
const DEFAULT_READY_TIMEOUT_SECS: u64 = 1_200;
const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 900;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;

#[derive(Clone, Debug)]
pub struct E2eConfig {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub target_host: String,
    pub ready_timeout: Duration,
    pub scan_timeout: Duration,
    pub poll_interval: Duration,
}

impl E2eConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            base_url: env_or_default("GVM_GATEWAY_E2E_BASE_URL", DEFAULT_BASE_URL),
            username: env_or_default("GVM_GATEWAY_E2E_USERNAME", DEFAULT_USERNAME),
            password: env_or_default("GVM_GATEWAY_E2E_PASSWORD", DEFAULT_PASSWORD),
            target_host: env_or_default("GVM_GATEWAY_E2E_TARGET_HOST", DEFAULT_TARGET_HOST),
            ready_timeout: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_READY_TIMEOUT_SECS",
                DEFAULT_READY_TIMEOUT_SECS,
            )?),
            scan_timeout: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_SCAN_TIMEOUT_SECS",
                DEFAULT_SCAN_TIMEOUT_SECS,
            )?),
            poll_interval: Duration::from_secs(env_u64_or_default(
                "GVM_GATEWAY_E2E_POLL_INTERVAL_SECS",
                DEFAULT_POLL_INTERVAL_SECS,
            )?),
        })
    }
}

pub struct E2eHarness {
    client: Client,
    pub config: E2eConfig,
}

impl E2eHarness {
    pub fn from_env() -> Result<Self> {
        let config = E2eConfig::from_env()?;
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("build reqwest client for E2E harness")?;
        Ok(Self { client, config })
    }

    pub async fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + self.config.ready_timeout;
        let mut last_observation = String::from("gateway readiness has not been queried yet");

        while Instant::now() < deadline {
            let response = self
                .client
                .get(self.endpoint("/ready"))
                .send()
                .await
                .context("query /ready")?;
            let status = response.status();
            let body = response.text().await.context("read /ready response body")?;

            if status == StatusCode::OK {
                let readiness: ReadinessResponse =
                    serde_json::from_str(&body).context("parse /ready success body")?;
                if readiness.status == "ready" {
                    eprintln!("gateway ready: {body}");
                    return Ok(());
                }
                last_observation = format!("readiness body reported non-ready state: {body}");
            } else {
                last_observation =
                    format!("readiness status {status} with body: {}", truncate(&body));
            }

            tokio::time::sleep(self.config.poll_interval).await;
        }

        bail!(
            "gateway did not become ready within {:?}: {last_observation}",
            self.config.ready_timeout
        );
    }

    pub async fn create_session(&self) -> Result<SessionResponse> {
        let request = self
            .client
            .post(self.endpoint("/api/v1/sessions"))
            .basic_auth(&self.config.username, Some(&self.config.password));
        self.send_json(request, StatusCode::CREATED, "create REST session")
            .await
    }

    pub async fn list_scan_configs(&self, token: &str) -> Result<Vec<ScanConfig>> {
        let response: ListResponse<ScanConfig> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/scan-configs", token),
                StatusCode::OK,
                "list scan configs",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_scan_config(&self, token: &str, scan_config_id: &str) -> Result<ScanConfig> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/scan-configs/{scan_config_id}"),
                token,
            ),
            StatusCode::OK,
            "get scan config",
        )
        .await
    }

    pub async fn list_scanners(&self, token: &str) -> Result<Vec<Scanner>> {
        let response: ListResponse<Scanner> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/scanners", token),
                StatusCode::OK,
                "list scanners",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn get_scanner(&self, token: &str, scanner_id: &str) -> Result<Scanner> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/scanners/{scanner_id}"),
                token,
            ),
            StatusCode::OK,
            "get scanner",
        )
        .await
    }

    pub async fn list_port_lists(&self, token: &str) -> Result<Vec<PortList>> {
        let response: ListResponse<PortList> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/port-lists", token),
                StatusCode::OK,
                "list port lists",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn create_port_list(
        &self,
        token: &str,
        name: &str,
        port_range: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E supporting resource coverage",
            "portRange": port_range,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/port-lists", token)
                .json(&body),
            "create port list",
        )
        .await
    }

    pub async fn get_port_list(&self, token: &str, port_list_id: &str) -> Result<PortList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/port-lists/{port_list_id}"),
                token,
            ),
            StatusCode::OK,
            "get port list",
        )
        .await
    }

    pub async fn delete_port_list(&self, token: &str, port_list_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/port-lists/{port_list_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete port list",
        )
        .await
    }

    pub async fn list_feeds(&self, token: &str) -> Result<Vec<Feed>> {
        let response: UnpaginatedListResponse<Feed> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/feeds", token),
                StatusCode::OK,
                "list feeds",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_timezones(&self, token: &str) -> Result<Vec<Timezone>> {
        let response: UnpaginatedListResponse<Timezone> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/timezones", token),
                StatusCode::OK,
                "list timezones",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_schedules(&self, token: &str) -> Result<ListResponse<Schedule>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/schedules?perPage=1000", token),
            StatusCode::OK,
            "list schedules",
        )
        .await
    }

    pub async fn create_schedule(
        &self,
        token: &str,
        name: &str,
        icalendar: &str,
        timezone: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E automation resource coverage",
            "icalendar": icalendar,
            "timezone": timezone,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/schedules", token)
                .json(&body),
            "create schedule",
        )
        .await
    }

    pub async fn get_schedule(&self, token: &str, schedule_id: &str) -> Result<Schedule> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/schedules/{schedule_id}"),
                token,
            ),
            StatusCode::OK,
            "get schedule",
        )
        .await
    }

    pub async fn delete_schedule(&self, token: &str, schedule_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/schedules/{schedule_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete schedule",
        )
        .await
    }

    pub async fn list_credential_stores(&self, token: &str) -> Result<Vec<CredentialStore>> {
        let response: UnpaginatedListResponse<CredentialStore> = self
            .send_json(
                self.authed(Method::GET, "/api/v1/credential-stores", token),
                StatusCode::OK,
                "list credential stores",
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_credentials(&self, token: &str) -> Result<ListResponse<Credential>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/credentials?perPage=1000", token),
            StatusCode::OK,
            "list credentials",
        )
        .await
    }

    pub async fn list_alerts(&self, token: &str) -> Result<ListResponse<Alert>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/alerts?perPage=1000", token),
            StatusCode::OK,
            "list alerts",
        )
        .await
    }

    pub async fn create_alert(&self, token: &str, name: &str) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E automation resource coverage",
            "event": "task_run_status_changed",
            "condition": "always",
            "method": "syslog",
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/alerts", token)
                .json(&body),
            "create alert",
        )
        .await
    }

    pub async fn get_alert(&self, token: &str, alert_id: &str) -> Result<Alert> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/alerts/{alert_id}"), token),
            StatusCode::OK,
            "get alert",
        )
        .await
    }

    pub async fn delete_alert(&self, token: &str, alert_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/alerts/{alert_id}"), token),
            StatusCode::NO_CONTENT,
            "delete alert",
        )
        .await
    }

    pub async fn create_username_password_credential(
        &self,
        token: &str,
        name: &str,
        login: &str,
        password: &str,
    ) -> Result<CreatedResource> {
        let body = json!({
            "name": name,
            "comment": "created by compose-backed E2E supporting resource coverage",
            "type": "up",
            "login": login,
            "password": password,
        });
        self.send_created_json(
            self.authed(Method::POST, "/api/v1/credentials", token)
                .json(&body),
            "create credential",
        )
        .await
    }

    pub async fn get_credential(&self, token: &str, credential_id: &str) -> Result<Credential> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/credentials/{credential_id}"),
                token,
            ),
            StatusCode::OK,
            "get credential",
        )
        .await
    }

    pub async fn delete_credential(&self, token: &str, credential_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/credentials/{credential_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete credential",
        )
        .await
    }

    pub async fn create_target(
        &self,
        token: &str,
        name: &str,
        port_list_id: &str,
    ) -> Result<Target> {
        let body = json!({
            "name": name,
            "hosts": [self.config.target_host.clone()],
            "aliveTest": "Consider Alive",
            "portListId": port_list_id,
        });
        let created: ResourceCreated = self
            .send_json(
                self.authed(Method::POST, "/api/v1/targets", token)
                    .json(&body),
                StatusCode::CREATED,
                "create target",
            )
            .await?;
        self.get_target(token, &created.id).await
    }

    pub async fn list_targets(&self, token: &str) -> Result<ListResponse<Target>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/targets?perPage=1000", token),
            StatusCode::OK,
            "list targets",
        )
        .await
    }

    pub async fn get_target(&self, token: &str, target_id: &str) -> Result<Target> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/targets/{target_id}"), token),
            StatusCode::OK,
            "get target",
        )
        .await
    }

    pub async fn delete_target(&self, token: &str, target_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(
                Method::DELETE,
                &format!("/api/v1/targets/{target_id}"),
                token,
            ),
            StatusCode::NO_CONTENT,
            "delete target",
        )
        .await
    }

    pub async fn create_task(
        &self,
        token: &str,
        name: &str,
        target_id: &str,
        scan_config_id: &str,
        scanner_id: &str,
    ) -> Result<Task> {
        let body = json!({
            "name": name,
            "targetId": target_id,
            "scanConfigId": scan_config_id,
            "scannerId": scanner_id,
        });
        let created: ResourceCreated = self
            .send_json(
                self.authed(Method::POST, "/api/v1/tasks", token)
                    .json(&body),
                StatusCode::CREATED,
                "create task",
            )
            .await?;
        self.get_task(token, &created.id).await
    }

    pub async fn list_tasks(&self, token: &str) -> Result<ListResponse<Task>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/tasks?perPage=1000", token),
            StatusCode::OK,
            "list tasks",
        )
        .await
    }

    pub async fn start_task(&self, token: &str, task_id: &str) -> Result<TaskAction> {
        self.send_json(
            self.authed(
                Method::POST,
                &format!("/api/v1/tasks/{task_id}/start"),
                token,
            ),
            StatusCode::OK,
            "start task",
        )
        .await
    }

    pub async fn delete_task(&self, token: &str, task_id: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, &format!("/api/v1/tasks/{task_id}"), token),
            StatusCode::NO_CONTENT,
            "delete task",
        )
        .await
    }

    pub async fn get_task(&self, token: &str, task_id: &str) -> Result<Task> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/tasks/{task_id}"), token),
            StatusCode::OK,
            "get task",
        )
        .await
    }

    pub async fn wait_for_task_completion(&self, token: &str, task_id: &str) -> Result<Task> {
        let deadline = Instant::now() + self.config.scan_timeout;
        let mut last_status = String::from("task status not yet observed");

        while Instant::now() < deadline {
            let task = self.get_task(token, task_id).await?;
            last_status = task.status.clone();
            eprintln!(
                "task {} status={} currentReport={:?} lastReport={:?}",
                task.id,
                task.status,
                task.current_report
                    .as_ref()
                    .map(|report| report.id.as_str()),
                task.last_report.as_ref().map(|report| report.id.as_str())
            );

            match task.status.as_str() {
                "Done" => return Ok(task),
                "Stopped" | "Interrupted" | "Delete Requested" | "Ultimate Delete Requested" => {
                    bail!(
                        "task {task_id} reached terminal failure status {}",
                        task.status
                    )
                }
                _ => tokio::time::sleep(self.config.poll_interval).await,
            }
        }

        bail!(
            "task {task_id} did not complete within {:?}; last status: {last_status}",
            self.config.scan_timeout
        );
    }

    pub async fn get_report(&self, token: &str, report_id: &str) -> Result<Report> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}?ignorePagination=true"),
                token,
            ),
            StatusCode::OK,
            "get report",
        )
        .await
    }

    pub async fn get_report_results(&self, token: &str, report_id: &str) -> Result<ResultList> {
        self.send_json(
            self.authed(
                Method::GET,
                &format!("/api/v1/reports/{report_id}/results"),
                token,
            ),
            StatusCode::OK,
            "get report results",
        )
        .await
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        let response = self
            .authed(Method::DELETE, &format!("/api/v1/sessions/{token}"), token)
            .send()
            .await
            .context("delete REST session")?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "delete session returned unexpected status {} with body {}",
            status,
            truncate(&body)
        );
    }

    pub fn select_discovery_scan_config<'a>(
        &self,
        scan_configs: &'a [ScanConfig],
    ) -> Result<&'a ScanConfig> {
        scan_configs
            .iter()
            .find(|config| lower(&config.name).contains("host discovery"))
            .or_else(|| {
                scan_configs
                    .iter()
                    .find(|config| lower(&config.name).contains("discovery"))
            })
            .with_context(|| {
                format!(
                    "no discovery scan config found; available configs: {}",
                    scan_configs
                        .iter()
                        .map(|config| config.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    pub fn select_scanner<'a>(&self, scanners: &'a [Scanner]) -> Result<&'a Scanner> {
        scanners
            .iter()
            .find(|scanner| {
                matches!(
                    scanner.scanner_type.as_deref(),
                    Some("OSP") | Some("OpenVAS")
                ) || lower(&scanner.name).contains("openvas")
            })
            .or_else(|| scanners.first())
            .with_context(|| "no scanners returned from REST API".to_string())
    }

    pub fn select_port_list<'a>(&self, port_lists: &'a [PortList]) -> Result<&'a PortList> {
        port_lists
            .iter()
            .find(|port_list| lower(&port_list.name).contains("all iana assigned tcp"))
            .or_else(|| {
                port_lists
                    .iter()
                    .find(|port_list| lower(&port_list.name).contains("all tcp"))
            })
            .or_else(|| port_lists.first())
            .with_context(|| "no port lists returned from REST API".to_string())
    }

    pub fn unique_name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", chrono_like_timestamp())
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    fn authed(&self, method: Method, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.endpoint(path))
            .bearer_auth(token)
    }

    async fn send_json<T>(
        &self,
        request: reqwest::RequestBuilder,
        expected_status: StatusCode,
        action: &str,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != expected_status {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                expected_status,
                status,
                truncate(&body)
            );
        }

        serde_json::from_str(&body)
            .with_context(|| format!("{action}: parse response body as JSON: {}", truncate(&body)))
    }

    async fn send_empty(
        &self,
        request: reqwest::RequestBuilder,
        expected_status: StatusCode,
        action: &str,
    ) -> Result<()> {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != expected_status {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                expected_status,
                status,
                truncate(&body)
            );
        }

        Ok(())
    }

    async fn send_created_json(
        &self,
        request: reqwest::RequestBuilder,
        action: &str,
    ) -> Result<CreatedResource> {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str())
            .transpose()
            .with_context(|| format!("{action}: parse Location response header"))?
            .map(ToOwned::to_owned);
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != StatusCode::CREATED {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                StatusCode::CREATED,
                status,
                truncate(&body)
            );
        }

        let body: ResourceCreated = serde_json::from_str(&body).with_context(|| {
            format!("{action}: parse response body as JSON: {}", truncate(&body))
        })?;
        let location = location
            .with_context(|| format!("{action}: response did not include Location header"))?;
        Ok(CreatedResource {
            id: body.id,
            location,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionResponse {
    #[serde(rename = "sessionToken")]
    pub token: String,
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
    #[serde(rename = "gmpVersion")]
    pub gmp_version: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceRef {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceCreated {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UnpaginatedListResponse<T> {
    pub data: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct CreatedResource {
    pub id: String,
    pub location: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Pagination {
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    pub total: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScanConfig {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Scanner {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub scanner_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PortList {
    pub id: String,
    pub name: String,
    #[serde(rename = "portCount")]
    pub port_count: Option<u32>,
    #[serde(rename = "tcpCount")]
    pub tcp_count: Option<u32>,
    #[serde(rename = "udpCount")]
    pub udp_count: Option<u32>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Feed {
    #[serde(rename = "type")]
    pub feed_type: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "currentlySyncing")]
    pub currently_syncing: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Timezone {
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub icalendar: Option<String>,
    pub timezone: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Alert {
    pub id: String,
    pub name: String,
    pub comment: Option<String>,
    pub event: Option<String>,
    pub condition: Option<String>,
    pub method: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CredentialStore {
    pub id: String,
    pub name: String,
    pub provider: Option<String>,
    pub default: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    pub login: Option<String>,
    #[serde(rename = "inUse")]
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    #[serde(rename = "portList")]
    pub port_list: Option<ResourceRef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub status: String,
    pub target: Option<ResourceRef>,
    #[serde(rename = "scanConfig")]
    pub scan_config: Option<ResourceRef>,
    pub scanner: Option<ResourceRef>,
    #[serde(rename = "currentReport")]
    pub current_report: Option<ResourceRef>,
    #[serde(rename = "lastReport")]
    pub last_report: Option<ResourceRef>,
    #[serde(rename = "resultCount")]
    pub result_count: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaskAction {
    #[serde(rename = "reportId")]
    pub report_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Report {
    pub id: String,
    pub task: Option<ResourceRef>,
    #[serde(rename = "scanEnd")]
    pub scan_end: Option<String>,
    #[serde(rename = "resultCount")]
    pub result_count: Option<ResultCount>,
    #[serde(default)]
    pub results: Vec<ScanResult>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResultCount {
    pub total: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub log: Option<u32>,
    #[serde(rename = "falsePositive")]
    pub false_positive: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResultList {
    pub data: Vec<ScanResult>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub name: String,
    pub host: Option<String>,
    pub port: Option<String>,
    pub severity: Option<f64>,
}

fn env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64_or_default(key: &str, default: u64) -> Result<u64> {
    match env::var(key) {
        Ok(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("parse {key}={raw} as u64")),
        Err(_) => Ok(default),
    }
}

fn truncate(body: &str) -> String {
    const LIMIT: usize = 400;
    if body.len() <= LIMIT {
        body.to_string()
    } else {
        format!("{}...", &body[..LIMIT])
    }
}

fn lower(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    now.to_string()
}
