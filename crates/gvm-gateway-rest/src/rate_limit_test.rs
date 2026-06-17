// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

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
    rate_limit_subject, ClientPeerAddr, RateBucket, RateLimitConfig, RateLimiter, TrustedProxyCidr,
    MAX_RATE_LIMIT_BUCKETS, X_FORWARDED_FOR,
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

fn trusted_loopback() -> Vec<TrustedProxyCidr> {
    vec!["127.0.0.1/32".parse().unwrap()]
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

    assert_eq!(rate_limit_subject(&request, &[]), "bearer:7731b204acf83e17");
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

    assert_eq!(rate_limit_subject(&request, &[]), "basic:53cfaadc3e07c384");
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

    assert_eq!(
        rate_limit_subject(&request, &[]),
        "session-create:ip:192.0.2.10"
    );
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

    assert_eq!(
        rate_limit_subject(&first, &[]),
        rate_limit_subject(&second, &[])
    );
}

#[test]
fn anonymous_subject_uses_source_ip_for_protected_routes() {
    // Missing credentials on protected routes must not collapse every
    // unauthenticated caller into one shared subject bucket.
    let first = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_000);
    let second = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 11), 40_001);

    assert_eq!(rate_limit_subject(&first, &[]), "anonymous:ip:192.0.2.10");
    assert_eq!(rate_limit_subject(&second, &[]), "anonymous:ip:192.0.2.11");
}

#[test]
fn anonymous_subject_ignores_ephemeral_port_for_protected_routes() {
    // A caller opening multiple connections from the same IP should still
    // consume the same unauthenticated protected-route bucket.
    let first = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_000);
    let second = request_from_ip("/api/v1/targets", Ipv4Addr::new(192, 0, 2, 10), 40_001);

    assert_eq!(
        rate_limit_subject(&first, &[]),
        rate_limit_subject(&second, &[])
    );
}

#[test]
fn trusted_proxy_session_creation_uses_forwarded_client_ip() {
    // In the container proxy deployment, the direct TCP peer is the proxy.
    // When that proxy is explicitly trusted, unauthenticated login pressure
    // must bucket by the original client IP instead of the shared proxy IP.
    let mut request = request_from_ip("/api/v1/session", Ipv4Addr::new(127, 0, 0, 1), 40_000);
    request
        .headers_mut()
        .insert(X_FORWARDED_FOR, "198.51.100.10".parse().unwrap());

    assert_eq!(
        rate_limit_subject(&request, &trusted_loopback()),
        "session-create:ip:198.51.100.10"
    );
}

#[test]
fn untrusted_peer_ignores_forwarded_client_ip() {
    // X-Forwarded-For is caller-controlled unless the direct peer is a
    // configured proxy, so spoofed headers must not move the bucket key.
    let mut request = request_from_ip("/api/v1/session", Ipv4Addr::new(203, 0, 113, 20), 40_000);
    request
        .headers_mut()
        .insert(X_FORWARDED_FOR, "198.51.100.10".parse().unwrap());

    assert_eq!(
        rate_limit_subject(&request, &trusted_loopback()),
        "session-create:ip:203.0.113.20"
    );
}

#[test]
fn malformed_forwarded_client_ip_falls_back_to_proxy_peer() {
    // A trusted proxy with a malformed forwarded header should fail closed
    // to the direct peer instead of creating an attacker-chosen bucket.
    let mut request = request_from_ip("/api/v1/session", Ipv4Addr::new(127, 0, 0, 1), 40_000);
    request
        .headers_mut()
        .insert(X_FORWARDED_FOR, "not-an-ip".parse().unwrap());

    assert_eq!(
        rate_limit_subject(&request, &trusted_loopback()),
        "session-create:ip:127.0.0.1"
    );
}

#[test]
fn trusted_proxy_uses_first_forwarded_client_ip() {
    // X-Forwarded-For is an ordered chain. The first address is the client
    // that should receive the unauthenticated session-creation bucket.
    let mut request = request_from_ip("/api/v1/session", Ipv4Addr::new(127, 0, 0, 1), 40_000);
    request.headers_mut().insert(
        X_FORWARDED_FOR,
        "198.51.100.10, 203.0.113.30".parse().unwrap(),
    );

    assert_eq!(
        rate_limit_subject(&request, &trusted_loopback()),
        "session-create:ip:198.51.100.10"
    );
}

#[test]
fn trusted_proxy_cidr_matches_ip_ranges() {
    // CIDR matching controls the trust boundary for forwarded source IPs.
    let cidr: TrustedProxyCidr = "192.0.2.0/24".parse().unwrap();

    assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 10))));
}

#[test]
fn poisoned_rate_limit_state_fails_closed() {
    // A panic while holding the limiter state must not turn rate limiting
    // into an allow-all path.
    let limiter = RateLimiter::new(
        RateLimitConfig {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: Some(10),
        },
        Vec::new(),
    );

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
    let limiter = RateLimiter::new(
        RateLimitConfig {
            window_secs: 60,
            global_per_window: None,
            subject_per_window: Some(10),
        },
        Vec::new(),
    );
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
