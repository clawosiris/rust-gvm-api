// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST rate-limiting configuration and runtime.

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::Request,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;

use crate::error::RestError;

/// Fixed-window REST rate-limit settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Fixed window length in seconds.
    pub window_secs: u64,
    /// Maximum API requests across all sessions in one window. `None` disables
    /// the global limit.
    pub global_per_window: Option<u64>,
    /// Maximum API requests per auth subject in one window. `None` disables
    /// the subject/session limit.
    pub subject_per_window: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            global_per_window: Some(1_000),
            subject_per_window: Some(500),
        }
    }
}

impl RateLimitConfig {
    /// Disable all rate limits. Useful for tests that need only unrelated
    /// router behavior.
    pub fn disabled() -> Self {
        Self {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<String, RateBucket>>,
}

#[derive(Clone, Debug)]
struct RateBucket {
    window_started_at: u64,
    count: u64,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn check_request(&self, request: &Request) -> Option<u64> {
        let now = now_secs();
        if let Some(limit) = self.config.global_per_window {
            if let Some(retry_after) = self.check_key("global".to_string(), limit, now) {
                return Some(retry_after);
            }
        }

        if let Some(limit) = self.config.subject_per_window {
            return self.check_key(rate_limit_subject(request), limit, now);
        }

        None
    }

    fn check_key(&self, key: String, limit: u64, now: u64) -> Option<u64> {
        if limit == 0 {
            return Some(self.config.window_secs.max(1));
        }

        let window_secs = self.config.window_secs.max(1);
        let mut buckets = self.buckets.lock().ok()?;
        buckets.retain(|_, bucket| now.saturating_sub(bucket.window_started_at) < window_secs);
        let bucket = buckets.entry(key).or_insert_with(|| RateBucket {
            window_started_at: now,
            count: 0,
        });

        if now.saturating_sub(bucket.window_started_at) >= window_secs {
            bucket.window_started_at = now;
            bucket.count = 0;
        }

        if bucket.count >= limit {
            Some(
                window_secs
                    .saturating_sub(now.saturating_sub(bucket.window_started_at))
                    .max(1),
            )
        } else {
            bucket.count += 1;
            None
        }
    }
}

pub(crate) fn is_rate_limited_path(path: &str) -> bool {
    path.starts_with("/api/v1/") && path != "/api/v1/openapi.json"
}

pub(crate) fn too_many_requests_response(instance: &str, retry_after_secs: u64) -> Response {
    let mut response = RestError::from_gateway_error(
        GatewayError::TooManyRequests(format!(
            "rate limit exceeded; retry after {retry_after_secs} seconds"
        )),
        instance.to_string(),
    )
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn rate_limit_subject(request: &Request) -> String {
    let path = request.uri().path();
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if let Some(token) = auth.strip_prefix("Bearer ") {
        return format!("bearer:{}", stable_hash(token));
    }
    if let Some(credentials) = auth.strip_prefix("Basic ") {
        return format!("basic:{}", stable_hash(credentials));
    }
    if path == "/api/v1/session" {
        return "session-create:anonymous".to_string();
    }
    "anonymous".to_string()
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
