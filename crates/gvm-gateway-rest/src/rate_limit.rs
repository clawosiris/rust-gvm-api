// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST rate-limiting configuration and runtime.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::ConnectInfo,
    extract::Request,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};
use gvm_gateway_domain::GatewayError;
use serde::Deserialize;

use crate::{error::RestError, peer_addr::ClientPeerAddr};

const MAX_RATE_LIMIT_BUCKETS: usize = 16_384;

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
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
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
            return self.check_key(rate_limit_subject(request), limit, now);
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

fn rate_limit_subject(request: &Request) -> String {
    let path = request.uri().path();
    if path == "/api/v1/session" {
        return format!("session-create:{}", source_subject(request));
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
    format!("anonymous:{}", source_subject(request))
}

fn source_subject(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<ClientPeerAddr>>()
        .map(|ConnectInfo(addr)| format!("ip:{}", addr.ip()))
        .unwrap_or_else(|| "unknown-source".to_string())
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
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        panic::{catch_unwind, AssertUnwindSafe},
    };

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{header, Request},
    };

    use super::{
        rate_limit_subject, ClientPeerAddr, RateBucket, RateLimitConfig, RateLimiter,
        MAX_RATE_LIMIT_BUCKETS,
    };

    fn request(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    fn request_from_ip(path: &str, ip: Ipv4Addr, port: u16) -> Request<Body> {
        let mut request = request(path);
        request
            .extensions_mut()
            .insert(ConnectInfo(ClientPeerAddr(SocketAddr::new(
                IpAddr::V4(ip),
                port,
            ))));
        request
    }

    #[test]
    fn bearer_subject_uses_intentional_stable_digest() {
        // This locks the rate-limit bucket contract so Rust hasher changes or
        // process restarts cannot reshuffle authenticated subjects.
        let mut request = request("/api/v1/targets");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer gvm_sess_secret".parse().unwrap(),
        );

        assert_eq!(rate_limit_subject(&request), "bearer:7731b204acf83e17");
    }

    #[test]
    fn basic_subject_uses_intentional_stable_digest() {
        // Request-scoped Basic auth remains separately bucketed without keeping
        // the credential material in the bucket key.
        let mut request = request("/api/v1/targets");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            "Basic YWRtaW46YWRtaW4=".parse().unwrap(),
        );

        assert_eq!(rate_limit_subject(&request), "basic:53cfaadc3e07c384");
    }

    #[test]
    fn session_creation_uses_source_ip_even_when_basic_auth_is_present() {
        // Session creation happens before the caller has an authenticated
        // subject, so brute-force pressure is bucketed by source address.
        let mut request = request("/api/v1/session");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            "Basic YWRtaW46YWRtaW4=".parse().unwrap(),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(ClientPeerAddr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                51_234,
            ))));

        assert_eq!(rate_limit_subject(&request), "session-create:ip:192.0.2.10");
    }

    #[test]
    fn session_creation_source_key_ignores_ephemeral_port() {
        // Multiple TCP connections from the same client IP must share the same
        // unauthenticated session-creation bucket.
        let mut first = request("/api/v1/session");
        first
            .extensions_mut()
            .insert(ConnectInfo(ClientPeerAddr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                40_000,
            ))));
        let mut second = request("/api/v1/session");
        second
            .extensions_mut()
            .insert(ConnectInfo(ClientPeerAddr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                40_001,
            ))));

        assert_eq!(rate_limit_subject(&first), rate_limit_subject(&second));
    }

    #[test]
    fn anonymous_subject_uses_source_ip_for_protected_routes() {
        // Missing credentials on protected routes must not collapse every
        // unauthenticated caller into one shared subject bucket.
        let first = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_000);
        let second = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 11), 40_001);

        assert_eq!(rate_limit_subject(&first), "anonymous:ip:192.0.2.10");
        assert_eq!(rate_limit_subject(&second), "anonymous:ip:192.0.2.11");
    }

    #[test]
    fn anonymous_subject_ignores_ephemeral_port_for_protected_routes() {
        // A caller opening multiple connections from the same IP should still
        // consume the same unauthenticated protected-route bucket.
        let first = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_000);
        let second = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_001);

        assert_eq!(rate_limit_subject(&first), rate_limit_subject(&second));
    }

    #[test]
    fn poisoned_rate_limit_state_fails_closed() {
        // A panic while holding the limiter state must not turn rate limiting
        // into an allow-all path.
        let limiter = RateLimiter::new(RateLimitConfig {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: Some(10),
        });

        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _state = limiter.state.lock().unwrap();
            panic!("poison rate-limit state");
        }))
        .is_err());

        assert_eq!(limiter.check_request(&request("/api/v1/targets")), Some(60));
    }

    #[test]
    fn bucket_capacity_rejects_new_subject_but_allows_existing_subject() {
        // The limiter must cap distinct bucket growth without breaking callers
        // that already have a bucket in the current window.
        let limiter = RateLimiter::new(RateLimitConfig {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: Some(10),
        });
        {
            let mut state = limiter.state.lock().unwrap();
            for index in 0..MAX_RATE_LIMIT_BUCKETS {
                state.buckets.insert(
                    format!("bearer:{index}"),
                    RateBucket {
                        window_started_at: 10,
                        count: 1,
                    },
                );
            }
            state.last_pruned_at = 10;
        }

        assert_eq!(limiter.check_key("bearer:0".to_string(), 10, 10), None);
        assert_eq!(
            limiter.check_key("bearer:new".to_string(), 10, 10),
            Some(60)
        );
    }
}
