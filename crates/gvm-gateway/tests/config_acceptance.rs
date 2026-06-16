use std::{collections::BTreeMap, io::Write};

use gvm_gateway::config::{
    load_config, load_config_with_default_path, parse_gvmd_endpoint, CliArgs, GatewayConfig,
    LocalLogOutput, SessionConfig, TransportSecurityConfig, TransportSecurityMode,
};
use gvm_gateway_domain::SessionLimits;
use gvm_gateway_rest::{
    peer_addr::TrustedProxyCidr,
    router::{RateLimitConfig, RestSecurityConfig},
};
use tempfile::{tempdir, NamedTempFile};

#[test]
fn default_config_valid() {
    // Covers the no-file path: without an explicit or canonical config file,
    // built-in defaults should still form a valid startup configuration.
    let dir = tempdir().unwrap();
    let missing_default_path = dir.path().join("missing-gvm-gateway.toml");
    let config =
        load_config_with_default_path(&CliArgs::default(), &BTreeMap::new(), &missing_default_path)
            .unwrap();
    assert_eq!(
        config,
        GatewayConfig {
            bind: "127.0.0.1:8080".to_string(),
            otlp_endpoint: None,
            telemetry_service_name: "gvm-gateway".to_string(),
            telemetry_service_namespace: Some("greenbone".to_string()),
            telemetry_deployment_environment: None,
            telemetry_service_instance_id: None,
            local_log_output: LocalLogOutput::Stdout,
            gvmd_endpoint: "unix:///run/gvmd/gvmd.sock".to_string(),
            shutdown_drain_timeout_secs: 30,
            session: SessionConfig::default(),
            rest_security: RestSecurityConfig::default(),
            transport_security: TransportSecurityConfig::default(),
        }
    );
}

#[test]
fn config_override_precedence() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "bind = \"127.0.0.1:8081\"\notlp_endpoint = \"http://collector:4317\"\ntelemetry_service_name = \"gateway-file\"\ntelemetry_service_namespace = \"greenbone.file\"\ntelemetry_deployment_environment = \"staging\"\ntelemetry_service_instance_id = \"gw-file-1\"\nlocal_log_output = \"journald\"\ngvmd_endpoint = \"unix:///tmp/gvmd.sock\"\nshutdown_drain_timeout_secs = 45\nsession_idle_timeout_secs = 120\nsession_max_global = 55\nsession_max_per_user = 5\ncors_allowed_origins = [\"https://ui.example\"]\nrate_limit_window_secs = 30\nrate_limit_global_per_window = 12\nrate_limit_subject_per_window = 3\ntrusted_proxy_cidrs = [\"10.0.0.0/8\"]"
    )
    .unwrap();

    let mut env = BTreeMap::new();
    env.insert("GVM_GATEWAY_BIND".to_string(), "0.0.0.0:9090".to_string());
    env.insert(
        "GVM_GATEWAY_TELEMETRY_SERVICE_NAME".to_string(),
        "gateway-env".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_TELEMETRY_SERVICE_INSTANCE_ID".to_string(),
        "gw-env-7".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_LOCAL_LOG_OUTPUT".to_string(),
        "stdout".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_GVMD_ENDPOINT".to_string(),
        "unix:///var/run/gvmd.sock".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_SHUTDOWN_DRAIN_TIMEOUT_SECS".to_string(),
        "5".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_SESSION_IDLE_TIMEOUT_SECS".to_string(),
        "600".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_SESSION_MAX_GLOBAL".to_string(),
        "0".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_SESSION_MAX_PER_USER".to_string(),
        "7".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_CORS_ALLOWED_ORIGINS".to_string(),
        "https://app.example, https://ops.example".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW".to_string(),
        "0".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_TRANSPORT_SECURITY_MODE".to_string(),
        "terminated_by_proxy".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_TRUSTED_PROXY_CIDRS".to_string(),
        "127.0.0.1/32, ::1/128".to_string(),
    );

    let config = load_config(
        &CliArgs {
            config: Some(file.path().to_path_buf()),
            bind: Some("127.0.0.1:3000".to_string()),
        },
        &env,
    )
    .unwrap();

    assert_eq!(config.bind, "127.0.0.1:3000");
    assert_eq!(
        config.otlp_endpoint.as_deref(),
        Some("http://collector:4317")
    );
    assert_eq!(config.telemetry_service_name, "gateway-env");
    assert_eq!(
        config.telemetry_service_namespace.as_deref(),
        Some("greenbone.file")
    );
    assert_eq!(
        config.telemetry_deployment_environment.as_deref(),
        Some("staging")
    );
    assert_eq!(
        config.telemetry_service_instance_id.as_deref(),
        Some("gw-env-7")
    );
    assert_eq!(config.local_log_output, LocalLogOutput::Stdout);
    assert_eq!(config.gvmd_endpoint, "unix:///var/run/gvmd.sock");
    assert_eq!(config.shutdown_drain_timeout_secs, 5);
    assert_eq!(
        config.session,
        SessionConfig {
            idle_timeout_secs: 600,
            limits: SessionLimits {
                max_global: None,
                max_per_user: Some(7),
            },
        }
    );
    assert_eq!(
        config.rest_security,
        RestSecurityConfig {
            cors_allowed_origins: vec![
                "https://app.example".to_string(),
                "https://ops.example".to_string()
            ],
            rate_limit: RateLimitConfig {
                window_secs: 30,
                global_per_window: Some(12),
                subject_per_window: None,
            },
            trusted_proxy_cidrs: vec![
                "127.0.0.1/32".parse::<TrustedProxyCidr>().unwrap(),
                "::1/128".parse::<TrustedProxyCidr>().unwrap(),
            ],
            native_tls_enabled: false,
        }
    );
    assert_eq!(
        config.transport_security,
        TransportSecurityConfig {
            mode: TransportSecurityMode::TerminatedByProxy,
            tls_certificate_path: None,
            tls_private_key_path: None,
        }
    );
}

#[test]
fn invalid_local_log_output_is_rejected() {
    let mut env = BTreeMap::new();
    env.insert(
        "GVM_GATEWAY_LOCAL_LOG_OUTPUT".to_string(),
        "syslog".to_string(),
    );

    let error = load_config(&CliArgs::default(), &env).unwrap_err();

    assert!(error
        .to_string()
        .contains("GVM_GATEWAY_LOCAL_LOG_OUTPUT must be one of: stdout, journald"));
}

#[test]
fn canonical_default_config_used_when_cli_config_omitted() {
    // Covers the package contract: admins may create the canonical config at
    // the default path, and startup without --config should honor it.
    let dir = tempdir().unwrap();
    let default_path = dir.path().join("gvm-gateway.toml");
    std::fs::write(
        &default_path,
        "bind = \"127.0.0.1:8181\"\ngvmd_endpoint = \"unix:///tmp/packaged-gvmd.sock\"",
    )
    .unwrap();

    let config =
        load_config_with_default_path(&CliArgs::default(), &BTreeMap::new(), &default_path)
            .unwrap();

    assert_eq!(config.bind, "127.0.0.1:8181");
    assert_eq!(config.gvmd_endpoint, "unix:///tmp/packaged-gvmd.sock");
}

#[test]
fn missing_canonical_default_config_keeps_builtin_defaults() {
    // Documents the default package install: the canonical config path is
    // optional, so a checkout or package with only .example still starts from
    // built-in defaults.
    let dir = tempdir().unwrap();
    let missing_default_path = dir.path().join("missing-gvm-gateway.toml");

    let config =
        load_config_with_default_path(&CliArgs::default(), &BTreeMap::new(), &missing_default_path)
            .unwrap();

    assert_eq!(config, GatewayConfig::default());
}

#[test]
fn explicit_cli_config_takes_priority_over_canonical_default_config() {
    // Protects the existing contract that --config selects the file layer
    // explicitly and is not blended with the packaged fallback file.
    let dir = tempdir().unwrap();
    let default_path = dir.path().join("gvm-gateway.toml");
    std::fs::write(&default_path, "bind = \"127.0.0.1:8181\"").unwrap();

    let mut explicit_file = NamedTempFile::new().unwrap();
    writeln!(explicit_file, "bind = \"127.0.0.1:8282\"").unwrap();

    let config = load_config_with_default_path(
        &CliArgs {
            config: Some(explicit_file.path().to_path_buf()),
            bind: None,
        },
        &BTreeMap::new(),
        &default_path,
    )
    .unwrap();

    assert_eq!(config.bind, "127.0.0.1:8282");
}

#[test]
fn parse_gvmd_endpoint_accepts_unix_uri_and_absolute_path() {
    assert_eq!(
        parse_gvmd_endpoint("unix:///run/gvmd/gvmd.sock").unwrap(),
        std::path::PathBuf::from("/run/gvmd/gvmd.sock")
    );
    assert_eq!(
        parse_gvmd_endpoint("/tmp/gvmd.sock").unwrap(),
        std::path::PathBuf::from("/tmp/gvmd.sock")
    );
}

#[test]
fn parse_gvmd_endpoint_rejects_unsupported_schemes() {
    let error = parse_gvmd_endpoint("tcp://gvmd:9390").unwrap_err();
    assert!(error
        .to_string()
        .contains("expected unix:///path/to/gvmd.sock"));
}

#[test]
fn native_transport_security_requires_both_tls_paths() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "transport_security_mode = \"native\"").unwrap();

    let error = load_config(
        &CliArgs {
            config: Some(file.path().to_path_buf()),
            bind: None,
        },
        &BTreeMap::new(),
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("tls_certificate_path must be set when transport_security_mode=native"));
}

#[test]
fn non_native_transport_security_rejects_tls_paths() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "transport_security_mode = \"terminated_by_proxy\"\ntls_certificate_path = \"/etc/gvm-gateway/tls/cert.pem\"\ntls_private_key_path = \"/etc/gvm-gateway/tls/key.pem\""
    )
    .unwrap();

    let error = load_config(
        &CliArgs {
            config: Some(file.path().to_path_buf()),
            bind: None,
        },
        &BTreeMap::new(),
    )
    .unwrap_err();

    assert!(error.to_string().contains(
        "terminated_by_proxy mode must not set tls_certificate_path or tls_private_key_path"
    ));
}

#[test]
fn native_transport_security_accepts_certificate_and_key_paths() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "transport_security_mode = \"native\"\ntls_certificate_path = \"/etc/gvm-gateway/tls/cert.pem\"\ntls_private_key_path = \"/etc/gvm-gateway/tls/key.pem\""
    )
    .unwrap();

    let config = load_config(
        &CliArgs {
            config: Some(file.path().to_path_buf()),
            bind: None,
        },
        &BTreeMap::new(),
    )
    .unwrap();

    assert_eq!(
        config.transport_security.mode,
        TransportSecurityMode::Native
    );
    assert_eq!(
        config.transport_security.tls_certificate_path,
        Some("/etc/gvm-gateway/tls/cert.pem".into())
    );
    assert_eq!(
        config.transport_security.tls_private_key_path,
        Some("/etc/gvm-gateway/tls/key.pem".into())
    );
}

#[test]
fn invalid_transport_security_mode_is_rejected() {
    let mut env = BTreeMap::new();
    env.insert(
        "GVM_GATEWAY_TRANSPORT_SECURITY_MODE".to_string(),
        "sometimes".to_string(),
    );

    let error = load_config(&CliArgs::default(), &env).unwrap_err();
    assert!(error
        .to_string()
        .contains("must be one of: disabled, terminated_by_proxy, native"));
}

#[test]
fn invalid_trusted_proxy_cidr_is_rejected() {
    // Trusted proxy CIDRs define whether caller-controlled forwarding headers
    // can affect rate-limit buckets, so bad values must fail startup.
    let mut env = BTreeMap::new();
    env.insert(
        "GVM_GATEWAY_TRUSTED_PROXY_CIDRS".to_string(),
        "127.0.0.1/999".to_string(),
    );

    let error = load_config(&CliArgs::default(), &env).unwrap_err();
    assert!(error
        .to_string()
        .contains("GVM_GATEWAY_TRUSTED_PROXY_CIDRS contains invalid CIDR"));
}
