// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OpenTelemetry and tracing setup for the gateway composition root.

use std::{
    io,
    sync::{Mutex, OnceLock},
};

use opentelemetry::{
    global, propagation::TextMapCompositePropagator, trace::TracerProvider as _, KeyValue,
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{BatchSpanProcessor, SdkTracerProvider},
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{GatewayConfig, LocalLogOutput};

fn tracer_provider_slot() -> &'static Mutex<Option<SdkTracerProvider>> {
    static TRACER_PROVIDER: OnceLock<Mutex<Option<SdkTracerProvider>>> = OnceLock::new();
    TRACER_PROVIDER.get_or_init(|| Mutex::new(None))
}

/// Initializes tracing and optional OTLP export.
pub fn init_tracing(
    config: &GatewayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);

    global::set_text_map_propagator(build_trace_propagator());

    if let Some(endpoint) = config.otlp_endpoint.as_ref() {
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let provider = SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(exporter).build())
            .with_resource(build_resource(config))
            .build();
        let tracer = provider.tracer(config.telemetry_service_name.clone());
        *tracer_provider_slot()
            .lock()
            .expect("tracer provider slot poisoned") = Some(provider.clone());
        global::set_tracer_provider(provider);
        match config.local_log_output {
            LocalLogOutput::Stdout => registry
                .with(tracing_subscriber::fmt::layer())
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()?,
            LocalLogOutput::Journald => registry
                .with(build_journald_layer(config)?)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()?,
        };
    } else {
        *tracer_provider_slot()
            .lock()
            .expect("tracer provider slot poisoned") = None;
        match config.local_log_output {
            LocalLogOutput::Stdout => registry.with(tracing_subscriber::fmt::layer()).try_init()?,
            LocalLogOutput::Journald => registry.with(build_journald_layer(config)?).try_init()?,
        };
    }

    Ok(())
}

fn build_journald_layer(
    config: &GatewayConfig,
) -> Result<tracing_journald::Layer, Box<dyn std::error::Error + Send + Sync>> {
    tracing_journald::layer()
        .map(|layer| layer.with_syslog_identifier(config.telemetry_service_name.clone()))
        .map_err(map_journald_init_error)
        .map_err(Into::into)
}

#[cfg(test)]
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

fn map_journald_init_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "failed to initialize journald log output: {error}. Ensure systemd-journald is available in this runtime or select local_log_output=\"stdout\""
        ),
    )
}

/// Flush any registered tracing provider before process exit.
pub fn shutdown_tracing() {
    if let Some(provider) = tracer_provider_slot()
        .lock()
        .expect("tracer provider slot poisoned")
        .take()
    {
        if let Err(error) = provider.shutdown() {
            tracing::warn!(?error, "failed to flush tracer provider during shutdown");
        }
    }
}

pub(crate) fn build_trace_propagator() -> TextMapCompositePropagator {
    TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ])
}

pub(crate) fn build_resource(config: &GatewayConfig) -> Resource {
    let mut attributes = vec![
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new(
            "service.namespace",
            config
                .telemetry_service_namespace
                .clone()
                .unwrap_or_else(|| "greenbone".to_string()),
        ),
    ];

    if let Some(environment) =
        non_empty_attribute(config.telemetry_deployment_environment.as_deref())
    {
        attributes.push(KeyValue::new("deployment.environment", environment));
    }

    if let Some(instance_id) = non_empty_attribute(config.telemetry_service_instance_id.as_deref())
    {
        attributes.push(KeyValue::new("service.instance.id", instance_id));
    }

    Resource::builder_empty()
        .with_service_name(config.telemetry_service_name.clone())
        .with_attributes(attributes)
        .build()
}

fn non_empty_attribute(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
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
            Err(io::Error::new(
                io::ErrorKind::Other,
                "journald factory should not be called for stdout mode",
            ))
        });

        assert!(layer.is_ok());
    }

    #[test]
    fn journald_local_logs_surface_clear_runtime_errors() {
        let mut config = GatewayConfig::default();
        config.local_log_output = LocalLogOutput::Journald;

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
}
