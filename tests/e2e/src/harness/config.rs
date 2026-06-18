// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{env, time::Duration};

use anyhow::{Context, Result};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_TARGET_HOST: &str = "openvasd";
const DEFAULT_READY_TIMEOUT_SECS: u64 = 1_200;
const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 900;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;
const DEFAULT_REPORT_FORMAT_PDF_ID: &str = "c402cc3e-b531-11e1-9163-406186ea4fc5";
const DEFAULT_REPORT_FORMAT_CSV_ID: &str = "c1645568-627a-11e3-a660-406186ea4fc5";

#[derive(Clone, Debug)]
pub struct E2eConfig {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub target_host: String,
    pub ready_timeout: Duration,
    pub scan_timeout: Duration,
    pub poll_interval: Duration,
    pub pdf_report_format_id: String,
    pub csv_report_format_id: String,
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
            pdf_report_format_id: env_or_default(
                "GVM_GATEWAY_E2E_REPORT_FORMAT_PDF_ID",
                DEFAULT_REPORT_FORMAT_PDF_ID,
            ),
            csv_report_format_id: env_or_default(
                "GVM_GATEWAY_E2E_REPORT_FORMAT_CSV_ID",
                DEFAULT_REPORT_FORMAT_CSV_ID,
            ),
        })
    }
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
