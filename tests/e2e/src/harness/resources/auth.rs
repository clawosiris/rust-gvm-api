// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn create_session(&self) -> Result<SessionResponse> {
        let request = self
            .client
            .post(self.endpoint("/api/v1/session"))
            .basic_auth(&self.config.username, Some(&self.config.password));
        self.send_json(request, StatusCode::CREATED, "create REST session")
            .await
    }

    pub async fn create_session_with_location(&self) -> Result<CreatedSession> {
        let response = self
            .client
            .post(self.endpoint("/api/v1/session"))
            .basic_auth(&self.config.username, Some(&self.config.password))
            .send()
            .await
            .context("create REST session with Location")?;
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str())
            .transpose()
            .context("parse session Location response header")?
            .map(ToOwned::to_owned);
        let body = response
            .text()
            .await
            .context("read create session response body")?;

        if status != StatusCode::CREATED {
            bail!(
                "create REST session: expected HTTP {} but received {} with body {}",
                StatusCode::CREATED,
                status,
                truncate(&body)
            );
        }

        let session: SessionResponse = serde_json::from_str(&body)
            .with_context(|| format!("parse session body as JSON: {}", truncate(&body)))?;
        let location =
            location.with_context(|| "create session response did not include Location header")?;
        Ok(CreatedSession { session, location })
    }

    pub async fn create_session_with_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<reqwest::Response> {
        self.request(Method::POST, "/api/v1/session")
            .basic_auth(username, Some(password))
            .send()
            .await
            .context("create REST session with supplied credentials")
    }

    pub async fn create_session_with_malformed_basic(&self) -> Result<reqwest::Response> {
        self.request(Method::POST, "/api/v1/session")
            .header(header::AUTHORIZATION, "Basic bm9fY29sb24=")
            .send()
            .await
            .context("create REST session with malformed Basic credentials")
    }

    pub async fn get_session(&self, token: &str) -> Result<SessionInfo> {
        self.send_json(
            self.authed(Method::GET, "/api/v1/session", token),
            StatusCode::OK,
            "get REST session",
        )
        .await
    }

    pub async fn get_session_response(&self, token: &str) -> Result<reqwest::Response> {
        self.authed(Method::GET, "/api/v1/session", token)
            .send()
            .await
            .context("get REST session response")
    }

    pub async fn get_targets_without_auth(&self) -> Result<reqwest::Response> {
        self.request(Method::GET, "/api/v1/targets")
            .send()
            .await
            .context("list targets without auth")
    }

    pub async fn get_targets_with_bearer(&self, token: &str) -> Result<reqwest::Response> {
        self.request(Method::GET, "/api/v1/targets")
            .bearer_auth(token)
            .send()
            .await
            .context("list targets with bearer token")
    }

    pub async fn get_targets_with_basic(
        &self,
        username: &str,
        password: &str,
    ) -> Result<reqwest::Response> {
        self.request(Method::GET, "/api/v1/targets")
            .basic_auth(username, Some(password))
            .send()
            .await
            .context("list targets with request-scoped Basic auth")
    }

    pub async fn get_users_without_auth(&self) -> Result<reqwest::Response> {
        self.request(Method::GET, "/api/v1/users")
            .send()
            .await
            .context("list users without auth")
    }

    pub async fn get_users_with_bearer(&self, token: &str) -> Result<reqwest::Response> {
        self.request(Method::GET, "/api/v1/users")
            .bearer_auth(token)
            .send()
            .await
            .context("list users with bearer token")
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        self.send_empty(
            self.authed(Method::DELETE, "/api/v1/session", token),
            StatusCode::NO_CONTENT,
            "delete session",
        )
        .await
    }
}
