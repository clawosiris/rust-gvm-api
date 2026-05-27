// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Feed-status and feed-sync use cases.

use gvm_gateway_domain::{Feed, GatewayError};

use crate::GatewayService;

impl GatewayService {
    /// Lists feed status for an authenticated session.
    pub async fn list_feeds(&self, session_token: &str) -> Result<Vec<Feed>, GatewayError> {
        self.execute_with_resource(
            "feeds.list",
            session_token,
            "list",
            "feed",
            None,
            |session| async move { self.feeds.list_feeds(&session.token).await },
        )
        .await
    }

    /// Triggers feed synchronization for an authenticated session.
    pub async fn sync_feeds(&self, session_token: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "feeds.sync",
            session_token,
            "sync",
            "feed",
            None,
            |session| async move { self.feeds.sync_feeds(&session.token).await },
        )
        .await
    }
}
