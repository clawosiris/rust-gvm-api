// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OpenTelemetry and tracing setup for the gateway composition root.

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

use crate::config::GatewayConfig;

/// Initializes tracing and optional OTLP export.
pub fn init_tracing(
    config: &GatewayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();
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
        global::set_tracer_provider(provider);
        registry
            .with(fmt_layer)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()?;
    } else {
        registry.with(fmt_layer).try_init()?;
    }

    Ok(())
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
    use opentelemetry::{propagation::TextMapPropagator, Key, Value};

    use super::*;

    fn test_config() -> GatewayConfig {
        GatewayConfig {
            otlp_endpoint: Some("http://collector:4317".to_string()),
            telemetry_service_name: "gateway-test".to_string(),
            telemetry_service_namespace: Some("greenbone.gateway".to_string()),
            telemetry_deployment_environment: Some("staging".to_string()),
            telemetry_service_instance_id: Some("gateway-01".to_string()),
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
}
