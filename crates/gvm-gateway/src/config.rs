// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Minimal config loading for the gateway composition root.

use std::{collections::BTreeMap, fs, path::PathBuf};

use clap::Parser;
use gvm_gateway_rest::router::RestSecurityConfig;
use serde::Deserialize;

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
    /// Backend socket path or endpoint.
    pub gvmd_endpoint: String,
    /// REST security middleware configuration.
    pub rest_security: RestSecurityConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            otlp_endpoint: None,
            gvmd_endpoint: "unix:///run/gvmd/gvmd.sock".to_string(),
            rest_security: RestSecurityConfig::default(),
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
    gvmd_endpoint: Option<String>,
    cors_allowed_origins: Option<Vec<String>>,
    rate_limit_window_secs: Option<u64>,
    rate_limit_global_per_window: Option<u64>,
    rate_limit_subject_per_window: Option<u64>,
}

/// Loads config from defaults, optional file, env map, and CLI overrides.
pub fn load_config(
    cli: &CliArgs,
    env: &BTreeMap<String, String>,
) -> Result<GatewayConfig, ConfigError> {
    let mut config = GatewayConfig::default();

    if let Some(path) = cli.config.as_ref() {
        let content = fs::read_to_string(path).map_err(ConfigError::Io)?;
        let file: FileConfig = toml::from_str(&content).map_err(ConfigError::ParseToml)?;
        if let Some(bind) = file.bind.as_ref() {
            config.bind = bind.clone();
        }
        if let Some(otlp_endpoint) = file.otlp_endpoint.as_ref() {
            config.otlp_endpoint = Some(otlp_endpoint.clone());
        }
        if let Some(gvmd_endpoint) = file.gvmd_endpoint.as_ref() {
            config.gvmd_endpoint = gvmd_endpoint.clone();
        }
        apply_security_file_config(&mut config.rest_security, &file);
    }

    if let Some(bind) = env.get("GVM_GATEWAY_BIND") {
        config.bind = bind.clone();
    }
    if let Some(otlp_endpoint) = env.get("GVM_GATEWAY_OTLP_ENDPOINT") {
        config.otlp_endpoint = Some(otlp_endpoint.clone());
    }
    if let Some(gvmd_endpoint) = env.get("GVM_GATEWAY_GVMD_ENDPOINT") {
        config.gvmd_endpoint = gvmd_endpoint.clone();
    }
    apply_security_env_config(&mut config.rest_security, env)?;

    if let Some(bind) = cli.bind.as_ref() {
        config.bind = bind.clone();
    }

    Ok(config)
}

fn apply_security_file_config(security: &mut RestSecurityConfig, file: &FileConfig) {
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
    Ok(())
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
