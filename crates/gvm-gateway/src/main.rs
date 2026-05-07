// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Composition root for the GVM gateway.

use std::{collections::BTreeMap, sync::Arc};

use clap::Parser;
use gvm_gateway_app::GatewayService;
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::router::build_router;
use tokio::net::TcpListener;

use gvm_gateway::{config::load_config, config::CliArgs, telemetry::init_tracing};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = CliArgs::parse();
    let env = std::env::vars().collect::<BTreeMap<_, _>>();
    let config = load_config(&cli, &env)?;
    init_tracing(&config)?;

    let listener = TcpListener::bind(&config.bind).await?;
    let system_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let target_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let task_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let auth_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let report_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let result_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let scan_config_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let scanner_adapter = Arc::new(StaticGvmdAdapter::ready("unknown"));
    let service = GatewayService::with_all(
        system_adapter,
        target_adapter,
        task_adapter,
        auth_adapter,
        report_adapter,
        result_adapter,
        scan_config_adapter,
        scanner_adapter,
    );
    let app = build_router(service);

    axum::serve(listener, app).await?;
    Ok(())
}
