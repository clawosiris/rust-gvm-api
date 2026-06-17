// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST rate-limiting configuration and runtime.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::ConnectInfo,
    extract::Request,
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;

use crate::{
    error::RestError,
    peer_addr::{ClientPeerAddr, TrustedProxyCidr},
};

const MAX_RATE_LIMIT_BUCKETS: usize = 16_384;
const X_FORWARDED_FOR: &str = "x-forwarded-for";

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
    trusted_proxy_cidrs: Vec<TrustedProxyCidr>,
    state: Mutex<RateLimitState>,
}

#[derive(Debug)]
struct RateLimitState {
    buckets: HashMap<String, RateBucket>,
    last_pruned_at: u64,
}

#[derive(Clone, Debug)]
struct RateBucket {
    window_started_at: u64,
    count: u64,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig, trusted_proxy_cidrs: Vec<TrustedProxyCidr>) -> Self {
        Self {
            config,
            trusted_proxy_cidrs,
            state: Mutex::new(RateLimitState {
                buckets: HashMap::new(),
                last_pruned_at: 0,
            }),
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
            return self.check_key(
                rate_limit_subject(request, &self.trusted_proxy_cidrs),
                limit,
                now,
            );
        }

        None
    }

    fn check_key(&self, key: String, limit: u64, now: u64) -> Option<u64> {
        if limit == 0 {
            return Some(self.config.window_secs.max(1));
        }

        let window_secs = self.config.window_secs.max(1);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                tracing::error!(
                    target: "gvm_gateway_rest::rate_limit",
                    error = %error,
                    "rate_limit_state_poisoned"
                );
                return Some(window_secs);
            }
        };

        if now.saturating_sub(state.last_pruned_at) >= 1 {
            prune_expired_buckets(&mut state, now, window_secs);
        }

        if !state.buckets.contains_key(&key) && state.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
            prune_expired_buckets(&mut state, now, window_secs);
            if state.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
                tracing::warn!(
                    target: "gvm_gateway_rest::rate_limit",
                    bucket_count = state.buckets.len(),
                    bucket_limit = MAX_RATE_LIMIT_BUCKETS,
                    "rate_limit_bucket_capacity_exhausted"
                );
                return Some(window_secs);
            }
        }

        let bucket = state.buckets.entry(key).or_insert_with(|| RateBucket {
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

fn prune_expired_buckets(state: &mut RateLimitState, now: u64, window_secs: u64) {
    state
        .buckets
        .retain(|_, bucket| now.saturating_sub(bucket.window_started_at) < window_secs);
    state.last_pruned_at = now;
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

fn rate_limit_subject(request: &Request, trusted_proxy_cidrs: &[TrustedProxyCidr]) -> String {
    let path = request.uri().path();
    if path == "/api/v1/session" {
        return format!(
            "session-create:{}",
            source_subject(request, trusted_proxy_cidrs)
        );
    }

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
    format!("anonymous:{}", source_subject(request, trusted_proxy_cidrs))
}

fn source_subject(request: &Request, trusted_proxy_cidrs: &[TrustedProxyCidr]) -> String {
    source_ip(request, trusted_proxy_cidrs)
        .map(|ip| format!("ip:{ip}"))
        .unwrap_or_else(|| "unknown-source".to_string())
}

fn source_ip(request: &Request, trusted_proxy_cidrs: &[TrustedProxyCidr]) -> Option<IpAddr> {
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<ClientPeerAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())?;

    if trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer_ip))
    {
        forwarded_for_client_ip(request.headers())
            .unwrap_or(peer_ip)
            .into()
    } else {
        Some(peer_ip)
    }
}

fn forwarded_for_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_FORWARDED_FOR)?
        .to_str()
        .ok()?
        .split(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn stable_hash(value: &str) -> String {
    let hash = value
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    format!("{hash:016x}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "rate_limit_test.rs"]
mod rate_limit_test;
