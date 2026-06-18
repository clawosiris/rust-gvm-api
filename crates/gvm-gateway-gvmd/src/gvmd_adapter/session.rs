// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::GatewayError;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

const MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING: usize = 64;

pub(super) struct SessionClient {
    client: AsyncMutex<GmpClient<UnixSocketConnection>>,
    command_slots: Arc<Semaphore>,
}

impl SessionClient {
    pub(super) fn new(client: GmpClient<UnixSocketConnection>) -> Self {
        Self {
            client: AsyncMutex::new(client),
            command_slots: Arc::new(Semaphore::new(MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING)),
        }
    }

    pub(super) async fn lock(&self) -> Result<SessionClientGuard<'_>, GatewayError> {
        let slot = Arc::clone(&self.command_slots)
            .try_acquire_owned()
            .map_err(|_| {
                GatewayError::TooManyRequests("session command queue saturated".to_string())
            })?;
        let guard = self.client.lock().await;
        Ok(SessionClientGuard { _slot: slot, guard })
    }
}

pub(super) struct SessionClientGuard<'a> {
    _slot: OwnedSemaphorePermit,
    guard: tokio::sync::MutexGuard<'a, GmpClient<UnixSocketConnection>>,
}

impl Deref for SessionClientGuard<'_> {
    type Target = GmpClient<UnixSocketConnection>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for SessionClientGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

pub(super) type SharedClient = Arc<SessionClient>;
