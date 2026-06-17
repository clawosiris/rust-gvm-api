// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl FeedPort for GvmdAdapter {
    async fn list_feeds(&self, session_token: &str) -> Result<Vec<Feed>, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_feeds())
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetFeedsResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.items.into_iter().map(feed_from_gmp).collect())
    }
}
