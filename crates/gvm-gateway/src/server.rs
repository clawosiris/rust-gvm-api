// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Server bootstrap helpers for graceful shutdown and bounded draining.

use std::future::IntoFuture;
use std::{sync::Arc, time::Duration};

use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use tokio::{net::TcpListener, time::timeout};

use crate::config::NativeTlsFiles;

/// Serve the gateway router until shutdown completes or the drain timeout elapses.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: Arc<ShutdownRuntime>,
    drain_timeout: Duration,
    native_tls: Option<NativeTlsFiles>,
) -> std::io::Result<()> {
    if let Some(native_tls) = native_tls {
        let handle = Handle::new();
        tokio::spawn({
            let shutdown = Arc::clone(&shutdown);
            let handle = handle.clone();
            async move {
                shutdown.wait_for_shutdown_start().await;
                tracing::info!(
                    drain_timeout_secs = drain_timeout.as_secs(),
                    in_flight_requests = shutdown.in_flight_requests(),
                    "shutdown: began graceful drain"
                );
                handle.graceful_shutdown(Some(drain_timeout));
            }
        });

        let config =
            RustlsConfig::from_pem_file(&native_tls.certificate_path, &native_tls.private_key_path)
                .await?;
        axum_server::from_tcp_rustls(listener.into_std()?, config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;

        if shutdown.is_shutting_down() {
            tracing::info!("shutdown: graceful drain completed");
        }

        shutdown.mark_stopped();
        return Ok(());
    }

    let server = axum::serve(listener, app)
        .with_graceful_shutdown({
            let shutdown = Arc::clone(&shutdown);
            async move {
                shutdown.wait_for_shutdown_start().await;
            }
        })
        .into_future();

    tokio::pin!(server);

    tokio::select! {
        result = &mut server => {
            result?;
        }
        _ = shutdown.wait_for_shutdown_start() => {
            tracing::info!(
                drain_timeout_secs = drain_timeout.as_secs(),
                in_flight_requests = shutdown.in_flight_requests(),
                "shutdown: began graceful drain"
            );

            match timeout(drain_timeout, async {
                shutdown.wait_for_zero_in_flight().await;
                server.await
            })
            .await
            {
                Ok(result) => {
                    result?;
                    tracing::info!("shutdown: graceful drain completed");
                }
                Err(_) => {
                    tracing::warn!(
                        drain_timeout_secs = drain_timeout.as_secs(),
                        in_flight_requests = shutdown.in_flight_requests(),
                        "shutdown: drain timeout reached; exiting with active requests"
                    );
                }
            }
        }
    }

    shutdown.mark_stopped();
    Ok(())
}
