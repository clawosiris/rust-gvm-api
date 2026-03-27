// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Minimal config loading for the gateway composition root.

use std::{collections::BTreeMap, fs, path::PathBuf};

use clap::Parser;
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
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            otlp_endpoint: None,
            gvmd_endpoint: "unix:///run/gvmd/gvmd.sock".to_string(),
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
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read config: {error}"),
            Self::ParseToml(error) => write!(f, "failed to parse config: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    otlp_endpoint: Option<String>,
    gvmd_endpoint: Option<String>,
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
        if let Some(bind) = file.bind {
            config.bind = bind;
        }
        if let Some(otlp_endpoint) = file.otlp_endpoint {
            config.otlp_endpoint = Some(otlp_endpoint);
        }
        if let Some(gvmd_endpoint) = file.gvmd_endpoint {
            config.gvmd_endpoint = gvmd_endpoint;
        }
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

    if let Some(bind) = cli.bind.as_ref() {
        config.bind = bind.clone();
    }

    Ok(config)
}
