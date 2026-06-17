// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::io;

use opentelemetry::{propagation::TextMapPropagator, Key, Value};

use super::*;

fn test_config() -> GatewayConfig {
    GatewayConfig {
        otlp_endpoint: Some("http://collector:4317".to_string()),
        telemetry_service_name: "gateway-test".to_string(),
        telemetry_service_namespace: Some("greenbone.gateway".to_string()),
        telemetry_deployment_environment: Some("staging".to_string()),
        telemetry_service_instance_id: Some("gateway-01".to_string()),
        local_log_output: LocalLogOutput::Stdout,
        ..GatewayConfig::default()
    }
}

fn prepare_local_log_output_with<F>(
    config: &GatewayConfig,
    journald_factory: F,
) -> Result<LocalLogOutput, Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce(&GatewayConfig) -> io::Result<()>,
{
    match config.local_log_output {
        LocalLogOutput::Stdout => Ok(LocalLogOutput::Stdout),
        LocalLogOutput::Journald => journald_factory(config)
            .map(|_| LocalLogOutput::Journald)
            .map_err(map_journald_init_error)
            .map_err(Into::into),
    }
}

#[test]
fn telemetry_resource_contains_stable_service_attributes() {
    let resource = build_resource(&test_config());

    assert_eq!(
        resource.get(&Key::new("service.name")),
        Some(Value::from("gateway-test"))
    );
    assert_eq!(
        resource.get(&Key::new("service.namespace")),
        Some(Value::from("greenbone.gateway"))
    );
    assert_eq!(
        resource.get(&Key::new("service.version")),
        Some(Value::from(env!("CARGO_PKG_VERSION")))
    );
    assert_eq!(
        resource.get(&Key::new("deployment.environment")),
        Some(Value::from("staging"))
    );
    assert_eq!(
        resource.get(&Key::new("service.instance.id")),
        Some(Value::from("gateway-01"))
    );
}

#[test]
fn telemetry_resource_omits_blank_optional_attributes() {
    let config = GatewayConfig {
        telemetry_deployment_environment: Some("   ".to_string()),
        telemetry_service_instance_id: Some(String::new()),
        ..GatewayConfig::default()
    };

    let resource = build_resource(&config);

    assert_eq!(
        resource.get(&Key::new("service.name")),
        Some(Value::from("gvm-gateway"))
    );
    assert_eq!(
        resource.get(&Key::new("service.namespace")),
        Some(Value::from("greenbone"))
    );
    assert_eq!(resource.get(&Key::new("deployment.environment")), None);
    assert_eq!(resource.get(&Key::new("service.instance.id")), None);
}

#[test]
fn trace_propagator_declares_all_supported_headers() {
    let propagator = build_trace_propagator();
    let fields = propagator.fields().map(str::to_string).collect::<Vec<_>>();

    assert!(fields.contains(&"traceparent".to_string()));
    assert!(fields.contains(&"tracestate".to_string()));
    assert!(fields.contains(&"baggage".to_string()));
}

#[test]
fn stdout_local_logs_do_not_attempt_journald_setup() {
    let layer = prepare_local_log_output_with(&GatewayConfig::default(), |_| {
        Err(io::Error::other(
            "journald factory should not be called for stdout mode",
        ))
    });

    assert!(layer.is_ok());
}

#[test]
fn journald_local_logs_surface_clear_runtime_errors() {
    let config = GatewayConfig {
        local_log_output: LocalLogOutput::Journald,
        ..GatewayConfig::default()
    };

    let error = prepare_local_log_output_with(&config, |_| {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "journald does not exist in this environment",
        ))
    })
    .unwrap_err()
    .to_string();

    assert!(error.contains("failed to initialize journald log output"));
    assert!(error.contains("select local_log_output=\"stdout\""));
}
