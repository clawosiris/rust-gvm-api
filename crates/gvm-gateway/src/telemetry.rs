// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 clawosiris

//! OpenTelemetry and tracing setup for the gateway composition root.

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::TracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::GatewayConfig;

/// Initializes tracing and optional OTLP export.
pub fn init_tracing(
    config: &GatewayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    if let Some(endpoint) = config.otlp_endpoint.as_ref() {
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);
        let provider = TracerProvider::builder()
            .with_batch_exporter(
                exporter.build_span_exporter()?,
                opentelemetry_sdk::runtime::Tokio,
            )
            .build();
        let tracer = provider.tracer("gvm-gateway");
        global::set_tracer_provider(provider);
        registry
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()?;
    } else {
        registry.with(tracing_subscriber::fmt::layer()).try_init()?;
    }

    Ok(())
}
