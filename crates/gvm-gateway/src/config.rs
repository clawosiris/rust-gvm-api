// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Minimal config loading for the gateway composition root.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use gvm_gateway_rest::{peer_addr::TrustedProxyCidr, router::RestSecurityConfig};
use serde::Deserialize;

/// Packaged config path used when no explicit `--config` path is provided.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/gvm-gateway/gvm-gateway.toml";

/// CLI arguments for gateway startup.
#[derive(Debug, Default, Parser)]
pub struct CliArgs {
    /// Optional config file path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Optional bind address override.
    #[arg(long)]
    pub bind: Option<String>,
}

/// Top-level gateway configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GatewayConfig {
    /// REST bind address.
    pub bind: String,
    /// Optional OTLP endpoint for tracing.
    pub otlp_endpoint: Option<String>,
    /// Stable OpenTelemetry service.name attribute.
    pub telemetry_service_name: String,
    /// Optional OpenTelemetry service.namespace attribute.
    pub telemetry_service_namespace: Option<String>,
    /// Optional OpenTelemetry deployment.environment attribute.
    pub telemetry_deployment_environment: Option<String>,
    /// Optional OpenTelemetry service.instance.id attribute.
    pub telemetry_service_instance_id: Option<String>,
    /// Backend socket path or endpoint.
    pub gvmd_endpoint: String,
    /// Maximum time to wait for in-flight requests during shutdown.
    pub shutdown_drain_timeout_secs: u64,
    /// REST security middleware configuration.
    pub rest_security: RestSecurityConfig,
    /// Transport security mode and native TLS material.
    pub transport_security: TransportSecurityConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            otlp_endpoint: None,
            telemetry_service_name: "gvm-gateway".to_string(),
            telemetry_service_namespace: Some("greenbone".to_string()),
            telemetry_deployment_environment: None,
            telemetry_service_instance_id: None,
            gvmd_endpoint: "unix:///run/gvmd/gvmd.sock".to_string(),
            shutdown_drain_timeout_secs: 30,
            rest_security: RestSecurityConfig::default(),
            transport_security: TransportSecurityConfig::default(),
        }
    }
}

impl GatewayConfig {
    /// Parse the configured gvmd endpoint into a Unix socket path.
    pub fn gvmd_socket_path(&self) -> Result<PathBuf, ConfigError> {
        parse_gvmd_endpoint(&self.gvmd_endpoint)
    }
}

/// Supported transport security modes for the REST gateway listener.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TransportSecurityMode {
    /// Serve plain HTTP intentionally.
    #[default]
    Disabled,
    /// Serve plain HTTP behind an upstream TLS-terminating proxy.
    TerminatedByProxy,
    /// Serve HTTPS directly from the gateway process.
    Native,
}

/// Gateway transport security configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct TransportSecurityConfig {
    /// Selected transport security mode.
    pub mode: TransportSecurityMode,
    /// PEM certificate path for native TLS mode.
    pub tls_certificate_path: Option<PathBuf>,
    /// PEM private-key path for native TLS mode.
    pub tls_private_key_path: Option<PathBuf>,
}

impl TransportSecurityConfig {
    /// Returns the native TLS files when native TLS is enabled.
    pub fn native_tls_files(&self) -> Result<Option<NativeTlsFiles>, ConfigError> {
        self.validate()?;

        if self.mode != TransportSecurityMode::Native {
            return Ok(None);
        }

        Ok(Some(NativeTlsFiles {
            certificate_path: require_path(
                "tls_certificate_path",
                self.tls_certificate_path.clone(),
            )?,
            private_key_path: require_path(
                "tls_private_key_path",
                self.tls_private_key_path.clone(),
            )?,
        }))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self.mode {
            TransportSecurityMode::Disabled | TransportSecurityMode::TerminatedByProxy => {
                if self.tls_certificate_path.is_some() || self.tls_private_key_path.is_some() {
                    return Err(ConfigError::InvalidValue(format!(
                        "{} mode must not set tls_certificate_path or tls_private_key_path",
                        self.mode.as_str()
                    )));
                }
            }
            TransportSecurityMode::Native => {
                require_path("tls_certificate_path", self.tls_certificate_path.clone())?;
                require_path("tls_private_key_path", self.tls_private_key_path.clone())?;
            }
        }

        Ok(())
    }
}

/// Native TLS certificate and private-key files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTlsFiles {
    /// PEM certificate path.
    pub certificate_path: PathBuf,
    /// PEM private-key path.
    pub private_key_path: PathBuf,
}

impl TransportSecurityMode {
    fn parse(value: &str, source: &str) -> Result<Self, ConfigError> {
        match value.trim() {
            "disabled" => Ok(Self::Disabled),
            "terminated_by_proxy" => Ok(Self::TerminatedByProxy),
            "native" => Ok(Self::Native),
            other => Err(ConfigError::InvalidValue(format!(
                "{source} must be one of: disabled, terminated_by_proxy, native (got '{other}')"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::TerminatedByProxy => "terminated_by_proxy",
            Self::Native => "native",
        }
    }
}

/// Errors that can occur while loading configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Configuration file could not be read.
    Io(std::io::Error),
    /// Configuration file was not valid TOML.
    ParseToml(toml::de::Error),
    /// Configuration contained an invalid value.
    InvalidValue(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read config: {error}"),
            Self::ParseToml(error) => write!(f, "failed to parse config: {error}"),
            Self::InvalidValue(error) => write!(f, "invalid config value: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    otlp_endpoint: Option<String>,
    telemetry_service_name: Option<String>,
    telemetry_service_namespace: Option<String>,
    telemetry_deployment_environment: Option<String>,
    telemetry_service_instance_id: Option<String>,
    gvmd_endpoint: Option<String>,
    shutdown_drain_timeout_secs: Option<u64>,
    cors_allowed_origins: Option<Vec<String>>,
    rate_limit_window_secs: Option<u64>,
    rate_limit_global_per_window: Option<u64>,
    rate_limit_subject_per_window: Option<u64>,
    trusted_proxy_cidrs: Option<Vec<String>>,
    transport_security_mode: Option<TransportSecurityMode>,
    tls_certificate_path: Option<PathBuf>,
    tls_private_key_path: Option<PathBuf>,
}

/// Loads config from defaults, optional file, env map, and CLI overrides.
pub fn load_config(
    cli: &CliArgs,
    env: &BTreeMap<String, String>,
) -> Result<GatewayConfig, ConfigError> {
    load_config_with_default_path(cli, env, Path::new(DEFAULT_CONFIG_PATH))
}

/// Loads config using an explicit fallback path for the packaged default file.
///
/// The fallback path is used only when `--config` is omitted. A missing fallback
/// file is ignored so local development without installed package files still
/// uses built-in defaults.
pub fn load_config_with_default_path(
    cli: &CliArgs,
    env: &BTreeMap<String, String>,
    default_config_path: &Path,
) -> Result<GatewayConfig, ConfigError> {
    let mut config = GatewayConfig::default();

    if let Some(content) = load_file_config(cli.config.as_deref(), default_config_path)? {
        let file: FileConfig = toml::from_str(&content).map_err(ConfigError::ParseToml)?;
        if let Some(bind) = file.bind.as_ref() {
            config.bind = bind.clone();
        }
        if let Some(otlp_endpoint) = file.otlp_endpoint.as_ref() {
            config.otlp_endpoint = Some(otlp_endpoint.clone());
        }
        if let Some(service_name) = file.telemetry_service_name.as_ref() {
            config.telemetry_service_name = service_name.clone();
        }
        if let Some(namespace) = file.telemetry_service_namespace.as_ref() {
            config.telemetry_service_namespace = Some(namespace.clone());
        }
        if let Some(environment) = file.telemetry_deployment_environment.as_ref() {
            config.telemetry_deployment_environment = Some(environment.clone());
        }
        if let Some(instance_id) = file.telemetry_service_instance_id.as_ref() {
            config.telemetry_service_instance_id = Some(instance_id.clone());
        }
        if let Some(gvmd_endpoint) = file.gvmd_endpoint.as_ref() {
            config.gvmd_endpoint = gvmd_endpoint.clone();
        }
        if let Some(timeout_secs) = file.shutdown_drain_timeout_secs {
            config.shutdown_drain_timeout_secs = timeout_secs;
        }
        if let Some(mode) = file.transport_security_mode {
            config.transport_security.mode = mode;
        }
        if let Some(path) = file.tls_certificate_path.as_ref() {
            config.transport_security.tls_certificate_path = Some(path.clone());
        }
        if let Some(path) = file.tls_private_key_path.as_ref() {
            config.transport_security.tls_private_key_path = Some(path.clone());
        }
        apply_security_file_config(&mut config.rest_security, &file)?;
    }

    if let Some(bind) = env.get("GVM_GATEWAY_BIND") {
        config.bind = bind.clone();
    }
    if let Some(otlp_endpoint) = env.get("GVM_GATEWAY_OTLP_ENDPOINT") {
        config.otlp_endpoint = Some(otlp_endpoint.clone());
    }
    if let Some(service_name) = env.get("GVM_GATEWAY_TELEMETRY_SERVICE_NAME") {
        config.telemetry_service_name = service_name.clone();
    }
    if let Some(namespace) = env.get("GVM_GATEWAY_TELEMETRY_SERVICE_NAMESPACE") {
        config.telemetry_service_namespace = Some(namespace.clone());
    }
    if let Some(environment) = env.get("GVM_GATEWAY_TELEMETRY_DEPLOYMENT_ENVIRONMENT") {
        config.telemetry_deployment_environment = Some(environment.clone());
    }
    if let Some(instance_id) = env.get("GVM_GATEWAY_TELEMETRY_SERVICE_INSTANCE_ID") {
        config.telemetry_service_instance_id = Some(instance_id.clone());
    }
    if let Some(gvmd_endpoint) = env.get("GVM_GATEWAY_GVMD_ENDPOINT") {
        config.gvmd_endpoint = gvmd_endpoint.clone();
    }
    if let Some(timeout_secs) = env.get("GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS") {
        config.shutdown_drain_timeout_secs =
            parse_u64("GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS", timeout_secs)?;
    }
    if let Some(mode) = env.get("GVM_GATEWAY_TRANSPORT_SECURITY_MODE") {
        config.transport_security.mode =
            TransportSecurityMode::parse(mode, "GVM_GATEWAY_TRANSPORT_SECURITY_MODE")?;
    }
    if let Some(path) = env.get("GVM_GATEWAY_TLS_CERTIFICATE_PATH") {
        config.transport_security.tls_certificate_path = Some(PathBuf::from(path));
    }
    if let Some(path) = env.get("GVM_GATEWAY_TLS_PRIVATE_KEY_PATH") {
        config.transport_security.tls_private_key_path = Some(PathBuf::from(path));
    }
    apply_security_env_config(&mut config.rest_security, env)?;

    if let Some(bind) = cli.bind.as_ref() {
        config.bind = bind.clone();
    }

    config.transport_security.validate()?;
    Ok(config)
}

fn load_file_config(
    explicit_path: Option<&Path>,
    default_config_path: &Path,
) -> Result<Option<String>, ConfigError> {
    if let Some(path) = explicit_path {
        return fs::read_to_string(path).map(Some).map_err(ConfigError::Io);
    }

    match fs::read_to_string(default_config_path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigError::Io(error)),
    }
}

/// Parse a configured gvmd endpoint into a Unix socket path.
///
/// The current runtime contract supports Unix domain sockets via
/// `unix:///path/to/gvmd.sock`, and also accepts a bare absolute socket path
/// for local development convenience.
pub fn parse_gvmd_endpoint(endpoint: &str) -> Result<PathBuf, ConfigError> {
    let value = endpoint.trim();
    if value.is_empty() {
        return Err(ConfigError::InvalidValue(
            "gvmd_endpoint must not be empty".to_string(),
        ));
    }

    if let Some(path) = value.strip_prefix("unix://") {
        return absolute_socket_path(path);
    }

    if value.starts_with('/') {
        return absolute_socket_path(value);
    }

    Err(ConfigError::InvalidValue(format!(
        "unsupported gvmd_endpoint '{value}'; expected unix:///path/to/gvmd.sock"
    )))
}

fn apply_security_file_config(
    security: &mut RestSecurityConfig,
    file: &FileConfig,
) -> Result<(), ConfigError> {
    if let Some(origins) = file.cors_allowed_origins.as_ref() {
        security.cors_allowed_origins = origins.clone();
    }
    if let Some(window_secs) = file.rate_limit_window_secs {
        security.rate_limit.window_secs = window_secs;
    }
    if let Some(limit) = file.rate_limit_global_per_window {
        security.rate_limit.global_per_window = limit_to_option(limit);
    }
    if let Some(limit) = file.rate_limit_subject_per_window {
        security.rate_limit.subject_per_window = limit_to_option(limit);
    }
    if let Some(cidrs) = file.trusted_proxy_cidrs.as_ref() {
        security.trusted_proxy_cidrs = parse_trusted_proxy_cidrs("trusted_proxy_cidrs", cidrs)?;
    }
    Ok(())
}

fn apply_security_env_config(
    security: &mut RestSecurityConfig,
    env: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    if let Some(origins) = env.get("GVM_GATEWAY_CORS_ALLOWED_ORIGINS") {
        security.cors_allowed_origins = origins
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    if let Some(window_secs) = env.get("GVM_GATEWAY_RATE_LIMIT_WINDOW_SECS") {
        security.rate_limit.window_secs =
            parse_u64("GVM_GATEWAY_RATE_LIMIT_WINDOW_SECS", window_secs)?;
    }
    if let Some(limit) = env.get("GVM_GATEWAY_RATE_LIMIT_GLOBAL_PER_WINDOW") {
        security.rate_limit.global_per_window = limit_to_option(parse_u64(
            "GVM_GATEWAY_RATE_LIMIT_GLOBAL_PER_WINDOW",
            limit,
        )?);
    }
    if let Some(limit) = env.get("GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW") {
        security.rate_limit.subject_per_window = limit_to_option(parse_u64(
            "GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW",
            limit,
        )?);
    }
    if let Some(cidrs) = env.get("GVM_GATEWAY_TRUSTED_PROXY_CIDRS") {
        let cidrs = cidrs
            .split(',')
            .map(str::trim)
            .filter(|cidr| !cidr.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        security.trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs("GVM_GATEWAY_TRUSTED_PROXY_CIDRS", &cidrs)?;
    }
    Ok(())
}

fn parse_trusted_proxy_cidrs(
    name: &str,
    cidrs: &[String],
) -> Result<Vec<TrustedProxyCidr>, ConfigError> {
    cidrs
        .iter()
        .map(|cidr| {
            cidr.parse::<TrustedProxyCidr>().map_err(|error| {
                ConfigError::InvalidValue(format!("{name} contains invalid CIDR '{cidr}': {error}"))
            })
        })
        .collect()
}

fn parse_u64(name: &str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidValue(format!("{name} must be an unsigned integer")))
}

fn limit_to_option(limit: u64) -> Option<u64> {
    if limit == 0 {
        None
    } else {
        Some(limit)
    }
}

fn absolute_socket_path(path: &str) -> Result<PathBuf, ConfigError> {
    let candidate = PathBuf::from(path);
    if !candidate.is_absolute() {
        return Err(ConfigError::InvalidValue(format!(
            "gvmd_endpoint must resolve to an absolute Unix socket path: {path}"
        )));
    }

    Ok(candidate)
}

fn require_path(name: &str, path: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    let path = path.ok_or_else(|| {
        ConfigError::InvalidValue(format!(
            "{name} must be set when transport_security_mode=native"
        ))
    })?;

    if path.as_os_str().is_empty() {
        return Err(ConfigError::InvalidValue(format!(
            "{name} must not be empty when transport_security_mode=native"
        )));
    }

    Ok(path)
}
