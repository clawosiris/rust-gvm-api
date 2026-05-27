// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Server bootstrap helpers for graceful shutdown and bounded draining.

use std::future::IntoFuture;
use std::{sync::Arc, time::Duration};

use axum::Router;
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use tokio::{net::TcpListener, time::timeout};

/// Serve the gateway router until shutdown completes or the drain timeout elapses.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: Arc<ShutdownRuntime>,
    drain_timeout: Duration,
) -> std::io::Result<()> {
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
