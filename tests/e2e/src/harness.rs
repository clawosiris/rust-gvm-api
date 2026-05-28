// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    env,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use reqwest::{Client, Method, StatusCode};
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

    pub async fn create_target(&self, token: &str, name: &str) -> Result<Target> {
        let body = json!({
            "name": name,
            "hosts": [self.config.target_host.clone()],
            "aliveTest": "Consider Alive",
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

    pub async fn get_target(&self, token: &str, target_id: &str) -> Result<Target> {
        self.send_json(
            self.authed(Method::GET, &format!("/api/v1/targets/{target_id}"), token),
            StatusCode::OK,
            "get target",
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
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionResponse {
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
pub struct Target {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(rename = "currentReport")]
    pub current_report: Option<ResourceRef>,
    #[serde(rename = "lastReport")]
    pub last_report: Option<ResourceRef>,
    #[serde(rename = "resultCount")]
    pub result_count: Option<ResultCount>,
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
        .as_secs();
    now.to_string()
}
