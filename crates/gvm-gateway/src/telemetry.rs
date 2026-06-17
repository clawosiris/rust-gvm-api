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
#[path = "telemetry_test.rs"]
mod telemetry_test;
