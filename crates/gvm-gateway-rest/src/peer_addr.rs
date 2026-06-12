// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Client peer address helpers used by REST middleware.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use axum::{extract::connect_info::Connected, serve::IncomingStream};
use serde::Deserialize;
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

/// CIDR range for a proxy whose forwarded client IP headers may be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedProxyCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxyCidr {
    /// Returns whether `ip` is inside this configured trusted proxy range.
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                ip_to_u32(ip) & ipv4_mask(self.prefix_len)
                    == ip_to_u32(network) & ipv4_mask(self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                ip_to_u128(ip) & ipv6_mask(self.prefix_len)
                    == ip_to_u128(network) & ipv6_mask(self.prefix_len)
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedProxyCidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (network, prefix_len) = value
            .trim()
            .split_once('/')
            .ok_or_else(|| "expected CIDR notation like 127.0.0.1/32".to_string())?;
        let network = network
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid CIDR network address '{network}'"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix length '{prefix_len}'"))?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "CIDR prefix length {prefix_len} exceeds maximum {max_prefix}"
            ));
        }

        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl<'de> Deserialize<'de> for TrustedProxyCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn ip_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}
