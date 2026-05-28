// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Composition root for the GVM gateway.

use std::{collections::BTreeMap, sync::Arc};

use clap::Parser;
use gvm_gateway_app::{GatewayService, SessionReaper};
use gvm_gateway_domain::SessionManager;
use gvm_gateway_gvmd::{GvmdAdapter, StaticGvmdAdapter};
use gvm_gateway_rest::{router::build_router_with_runtime_and_security, shutdown::ShutdownRuntime};
use tokio::net::TcpListener;

use gvm_gateway::{config::load_config, config::CliArgs, server, telemetry::init_tracing};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = CliArgs::parse();
    let env = std::env::vars().collect::<BTreeMap<_, _>>();
    let config = load_config(&cli, &env)?;
    init_tracing(&config)?;

    let gvmd_socket_path = config.gvmd_socket_path()?;
    let native_tls = config.transport_security.native_tls_files()?;
    let listener = TcpListener::bind(&config.bind).await?;
    let live_adapter = Arc::new(GvmdAdapter::unix_socket(&gvmd_socket_path));
    let system_adapter = Arc::new(probe_system_adapter(&live_adapter).await);
    let sessions = Arc::new(SessionManager::default());
    let reaper = SessionReaper::new(Arc::clone(&sessions), live_adapter.clone());
    let service = gateway_service(system_adapter, live_adapter, sessions);
    let _reaper_handle = reaper.spawn();
    let shutdown = Arc::new(ShutdownRuntime::new());
    let app = build_router_with_runtime_and_security(
        service,
        Arc::clone(&shutdown),
        config.rest_security,
    );

    tokio::spawn({
        let shutdown = Arc::clone(&shutdown);
        async move {
            wait_for_shutdown_signal().await;
            if shutdown.begin_shutdown() {
                tracing::info!("shutdown: received termination signal");
            }
        }
    });

    server::serve(
        listener,
        app,
        shutdown,
        std::time::Duration::from_secs(config.shutdown_drain_timeout_secs),
        native_tls,
    )
    .await?;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate =
            signal(SignalKind::terminate()).expect("SIGTERM signal handler must initialize");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn gateway_service(
    system_adapter: Arc<StaticGvmdAdapter>,
    live_adapter: Arc<GvmdAdapter>,
    sessions: Arc<SessionManager>,
) -> GatewayService {
    GatewayService::new(
        system_adapter,
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter.clone(),
        live_adapter,
        sessions,
    )
}

async fn probe_system_adapter(adapter: &GvmdAdapter) -> StaticGvmdAdapter {
    match adapter.probe_version().await {
        Ok(version) => StaticGvmdAdapter::ready(version),
        Err(error) => {
            tracing::warn!(
                ?error,
                "startup gvmd probe failed; continuing with an unknown GMP version until gvmd is reachable"
            );
            StaticGvmdAdapter::ready("unknown")
        }
    }
}
