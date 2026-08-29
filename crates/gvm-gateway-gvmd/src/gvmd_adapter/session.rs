// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::{
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
};

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gateway_domain::GatewayError;
use gvm_gmp::{commands::authentication::authenticate, responses::AuthenticateResponse};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

use crate::conversions::{map_gvm_error, map_parse_error};

const MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING: usize = 64;

pub(super) struct SessionClient {
    client: AsyncMutex<GmpClient<UnixSocketConnection>>,
    command_slots: Arc<Semaphore>,
    username: String,
    password: String,
}

impl SessionClient {
    pub(super) fn new(
        client: GmpClient<UnixSocketConnection>,
        username: String,
        password: String,
    ) -> Self {
        Self {
            client: AsyncMutex::new(client),
            command_slots: Arc::new(Semaphore::new(MAX_SESSION_COMMANDS_IN_FLIGHT_OR_WAITING)),
            username,
            password,
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

    pub(super) fn auth_pair_owned(&self) -> (String, String) {
        (self.username.clone(), self.password.clone())
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

impl SessionClientGuard<'_> {
    pub(super) async fn reconnect(
        &mut self,
        socket_path: &Path,
        username: &str,
        password: &str,
    ) -> Result<(), GatewayError> {
        let connection = UnixSocketConnection::with_path(socket_path);
        let mut client = GmpClient::connect(connection)
            .await
            .map_err(map_gvm_error)?;
        let response = client
            .call(authenticate(username, password))
            .await
            .map_err(map_gvm_error)?;
        AuthenticateResponse::from_response(&response).map_err(map_parse_error)?;
        *self.guard = client;
        Ok(())
    }
}

pub(super) type SharedClient = Arc<SessionClient>;

#[cfg(test)]
#[path = "session_test.rs"]
mod session_test;
