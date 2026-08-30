// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::{header, Client, Method, StatusCode};
use serde_json::json;

mod assertions;
mod config;
mod dto;
mod http;
mod polling;
mod resources;

#[cfg(test)]
mod dto_test;

pub use assertions::{assert_problem_response, assert_problem_response_any};
pub use config::E2eConfig;
pub use dto::*;

use http::truncate;

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

    pub fn unique_name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", chrono_like_timestamp())
    }

    pub fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client.request(method, self.endpoint(path))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    fn authed(&self, method: Method, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.request(method, path).bearer_auth(token)
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
