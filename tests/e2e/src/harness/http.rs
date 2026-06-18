// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use anyhow::{bail, Context, Result};
use reqwest::{header, StatusCode};
use serde::de::DeserializeOwned;

use super::{CreatedResource, E2eHarness, ResourceCreated};

impl E2eHarness {
    pub(super) async fn send_json<T>(
        &self,
        request: reqwest::RequestBuilder,
        expected_status: StatusCode,
        action: &str,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != expected_status {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                expected_status,
                status,
                truncate(&body)
            );
        }

        serde_json::from_str(&body)
            .with_context(|| format!("{action}: parse response body as JSON: {}", truncate(&body)))
    }

    pub(super) async fn send_empty(
        &self,
        request: reqwest::RequestBuilder,
        expected_status: StatusCode,
        action: &str,
    ) -> Result<()> {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != expected_status {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                expected_status,
                status,
                truncate(&body)
            );
        }

        Ok(())
    }

    pub(super) async fn send_created_json(
        &self,
        request: reqwest::RequestBuilder,
        action: &str,
    ) -> Result<CreatedResource> {
        let response = request
            .send()
            .await
            .with_context(|| format!("{action}: send HTTP request"))?;
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str())
            .transpose()
            .with_context(|| format!("{action}: parse Location response header"))?
            .map(ToOwned::to_owned);
        let body = response
            .text()
            .await
            .with_context(|| format!("{action}: read HTTP response body"))?;

        if status != StatusCode::CREATED {
            bail!(
                "{action}: expected HTTP {} but received {} with body {}",
                StatusCode::CREATED,
                status,
                truncate(&body)
            );
        }

        let body: ResourceCreated = serde_json::from_str(&body).with_context(|| {
            format!("{action}: parse response body as JSON: {}", truncate(&body))
        })?;
        let location = location
            .with_context(|| format!("{action}: response did not include Location header"))?;
        Ok(CreatedResource {
            id: body.id,
            location,
        })
    }
}

pub(super) fn truncate(body: &str) -> String {
    const LIMIT: usize = 400;
    if body.len() <= LIMIT {
        body.to_string()
    } else {
        format!("{}...", &body[..LIMIT])
    }
}
