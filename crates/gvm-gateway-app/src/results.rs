// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Result use cases.

use gvm_gateway_domain::{GatewayError, ResultPage, ResultQuery, ScanResult};

use crate::GatewayService;

impl GatewayService {
    /// Lists results for an authenticated session.
    pub async fn list_results(
        &self,
        session_token: &str,
        query: ResultQuery,
    ) -> Result<ResultPage, GatewayError> {
        self.execute_with_resource(
            "results.list",
            session_token,
            "list",
            "result",
            None,
            |session| async move { self.results.list_results(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a result for an authenticated session.
    pub async fn get_result(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanResult, GatewayError> {
        self.execute_with_resource(
            "results.get",
            session_token,
            "read",
            "result",
            Some(id),
            |session| async move { self.results.get_result(&session.token, id).await },
        )
        .await
    }
}
