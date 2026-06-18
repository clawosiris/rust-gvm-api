// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl AuthPort for GvmdAdapter {
    async fn authenticate_session(
        &self,
        session_token: &str,
        username: &str,
        password: &str,
    ) -> Result<String, GatewayError> {
        self.connect_session(session_token, username, password)
            .await
    }

    async fn disconnect_session(&self, session: &SessionTokenDigest) -> Result<(), GatewayError> {
        self.sessions
            .lock()
            .map_err(|_| GatewayError::BackendUnavailable("session store unavailable".to_string()))?
            .remove(session);
        Ok(())
    }
}
