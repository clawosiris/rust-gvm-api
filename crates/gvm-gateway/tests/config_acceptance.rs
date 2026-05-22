use std::{collections::BTreeMap, io::Write};

use gvm_gateway::config::{load_config, CliArgs, GatewayConfig};
use gvm_gateway_rest::router::{RateLimitConfig, RestSecurityConfig};
use tempfile::NamedTempFile;

#[test]
fn default_config_valid() {
    let config = load_config(&CliArgs::default(), &BTreeMap::new()).unwrap();
    assert_eq!(
        config,
        GatewayConfig {
            bind: "127.0.0.1:8080".to_string(),
            otlp_endpoint: None,
            gvmd_endpoint: "unix:///run/gvmd/gvmd.sock".to_string(),
            rest_security: RestSecurityConfig::default(),
        }
    );
}

#[test]
fn config_override_precedence() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "bind = \"127.0.0.1:8081\"\notlp_endpoint = \"http://collector:4317\"\ngvmd_endpoint = \"unix:///tmp/gvmd.sock\"\ncors_allowed_origins = [\"https://ui.example\"]\nrate_limit_window_secs = 30\nrate_limit_global_per_window = 12\nrate_limit_subject_per_window = 3"
    )
    .unwrap();

    let mut env = BTreeMap::new();
    env.insert("GVM_GATEWAY_BIND".to_string(), "0.0.0.0:9090".to_string());
    env.insert(
        "GVM_GATEWAY_GVMD_ENDPOINT".to_string(),
        "unix:///var/run/gvmd.sock".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_CORS_ALLOWED_ORIGINS".to_string(),
        "https://app.example, https://ops.example".to_string(),
    );
    env.insert(
        "GVM_GATEWAY_RATE_LIMIT_SUBJECT_PER_WINDOW".to_string(),
        "0".to_string(),
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
    assert_eq!(config.gvmd_endpoint, "unix:///var/run/gvmd.sock");
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
        }
    );
}
