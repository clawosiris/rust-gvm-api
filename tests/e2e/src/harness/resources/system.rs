// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn get_health(&self) -> Result<HealthResponse> {
        self.send_json(
            self.request(Method::GET, "/health"),
            StatusCode::OK,
            "get gateway health",
        )
        .await
    }

    pub async fn get_readiness(&self) -> Result<ReadinessResponse> {
        self.send_json(
            self.request(Method::GET, "/ready"),
            StatusCode::OK,
            "get gateway readiness",
        )
        .await
    }

    pub async fn get_version(&self) -> Result<VersionResponse> {
        self.send_json(
            self.request(Method::GET, "/api/v1/version"),
            StatusCode::OK,
            "get gateway version",
        )
        .await
    }

    pub async fn get_timezones(
        &self,
        token: &str,
    ) -> Result<UnpaginatedListResponse<TimezoneEntry>> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/timezones", token),
            StatusCode::OK,
            "get backend timezones",
        )
        .await
    }
}
