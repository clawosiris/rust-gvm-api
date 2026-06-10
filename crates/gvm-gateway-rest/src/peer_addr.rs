// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Client peer address type used by REST middleware.

use std::net::{IpAddr, SocketAddr};

use axum::{extract::connect_info::Connected, serve::IncomingStream};
use tokio::net::TcpListener;

/// Peer socket address recorded by the server accept path.
#[derive(Clone, Copy, Debug)]
pub struct ClientPeerAddr(pub SocketAddr);

impl ClientPeerAddr {
    /// Returns the peer IP address without the ephemeral source port.
    pub fn ip(self) -> IpAddr {
        self.0.ip()
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for ClientPeerAddr {
    fn connect_info(target: IncomingStream<'_, TcpListener>) -> Self {
        Self(*target.remote_addr())
    }
}
