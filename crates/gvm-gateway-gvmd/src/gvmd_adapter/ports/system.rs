// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl SystemPort for GvmdAdapter {
    async fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
        match self.probe_version().await {
            Ok(_) => Ok(ReadinessStatus {
                status: "ready",
                reason: None,
            }),
            Err(error) => Ok(ReadinessStatus {
                status: "notReady",
                reason: Some(error.detail().to_string()),
            }),
        }
    }

    async fn gmp_version(&self) -> Result<String, GatewayError> {
        self.probe_version().await
    }

    async fn list_timezones(&self, session_token: &str) -> Result<Vec<Timezone>, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_timezones())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetTimezonesResponse::from_response(&response).map_err(map_parse_error)?;

        Ok(parsed.items.into_iter().map(timezone_from_gmp).collect())
    }
}
