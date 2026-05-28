// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Server bootstrap helpers for graceful shutdown and bounded draining.

use std::{
    future::Future, future::IntoFuture, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use axum::Router;
use gvm_gateway_rest::shutdown::ShutdownRuntime;
use tokio::{net::TcpListener, net::TcpStream, time::timeout};
use tokio_rustls::{
    rustls::{
        pki_types::pem::PemObject, pki_types::CertificateDer, pki_types::PrivateKeyDer,
        ServerConfig,
    },
    server::TlsStream,
    TlsAcceptor,
};

use crate::config::NativeTlsFiles;

/// Serve the gateway router until shutdown completes or the drain timeout elapses.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: Arc<ShutdownRuntime>,
    drain_timeout: Duration,
    native_tls: Option<NativeTlsFiles>,
) -> std::io::Result<()> {
    let server: Pin<Box<dyn Future<Output = io::Result<()>> + Send>> =
        if let Some(native_tls) = native_tls {
            let tls_listener = TlsListener::new(listener, load_tls_config(&native_tls)?);
            Box::pin(
                axum::serve(tls_listener, app)
                    .with_graceful_shutdown({
                        let shutdown = Arc::clone(&shutdown);
                        async move {
                            shutdown.wait_for_shutdown_start().await;
                        }
                    })
                    .into_future(),
            )
        } else {
            Box::pin(
                axum::serve(listener, app)
                    .with_graceful_shutdown({
                        let shutdown = Arc::clone(&shutdown);
                        async move {
                            shutdown.wait_for_shutdown_start().await;
                        }
                    })
                    .into_future(),
            )
        };

    serve_with_drain(server, shutdown, drain_timeout).await
}

async fn serve_with_drain(
    server: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
    shutdown: Arc<ShutdownRuntime>,
    drain_timeout: Duration,
) -> io::Result<()> {
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

fn load_tls_config(native_tls: &NativeTlsFiles) -> io::Result<Arc<ServerConfig>> {
    let certificates = CertificateDer::pem_file_iter(&native_tls.certificate_path)
        .map_err(|error| invalid_tls_data("certificate", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_tls_data("certificate", error))?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid native TLS certificate file '{}': no PEM certificates found",
                native_tls.certificate_path.display()
            ),
        ));
    }

    let private_key = PrivateKeyDer::from_pem_file(&native_tls.private_key_path)
        .map_err(|error| invalid_tls_data("private key", error))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build native TLS server config: {error}"),
            )
        })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn invalid_tls_data(kind: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid native TLS {kind}: {error}"),
    )
}

struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, remote_addr) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    handle_accept_error(error).await;
                    continue;
                }
            };

            if let Err(error) = stream.set_nodelay(true) {
                tracing::trace!(?error, %remote_addr, "failed to set TCP_NODELAY on native TLS connection");
            }

            match self.acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, remote_addr),
                Err(error) => {
                    tracing::warn!(?error, %remote_addr, "native TLS handshake failed");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn handle_accept_error(error: io::Error) {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }

    tracing::error!(?error, "accept error");
    tokio::time::sleep(Duration::from_secs(1)).await;
}
