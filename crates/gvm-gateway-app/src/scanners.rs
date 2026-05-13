// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Scanner use cases.

use gvm_gateway_domain::{GatewayError, Scanner, ScannerPage, ScannerQuery};

use crate::GatewayService;

impl GatewayService {
    /// Lists scanners for an authenticated session.
    pub async fn list_scanners(
        &self,
        session_token: &str,
        query: ScannerQuery,
    ) -> Result<ScannerPage, GatewayError> {
        self.execute_with_resource(
            "scanners.list",
            session_token,
            "list",
            "scanner",
            None,
            |session| async move { self.scanners.list_scanners(&session.token, &query).await },
        )
        .await
    }

    /// Fetches a scanner for an authenticated session.
    pub async fn get_scanner(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Scanner, GatewayError> {
        self.execute_with_resource(
            "scanners.get",
            session_token,
            "read",
            "scanner",
            Some(id),
            |session| async move { self.scanners.get_scanner(&session.token, id).await },
        )
        .await
    }
}
