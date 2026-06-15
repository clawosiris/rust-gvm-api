// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Alert use cases.

use gvm_gateway_domain::{
    Alert, AlertPage, AlertQuery, CreateAlertInput, GatewayError, ModifyAlertInput,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists alerts for an authenticated session.
    pub async fn list_alerts(
        &self,
        session_token: &str,
        query: AlertQuery,
    ) -> Result<AlertPage, GatewayError> {
        self.execute_with_resource(
            "alerts.list",
            session_token,
            "list",
            "alert",
            None,
            |session| async move { self.alerts.list_alerts(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new alert for an authenticated session.
    pub async fn create_alert(
        &self,
        session_token: &str,
        input: CreateAlertInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "alerts.create",
            session_token,
            "create",
            "alert",
            None,
            |session| async move { self.alerts.create_alert(&session.token, input).await },
        )
        .await
    }

    /// Fetches an alert for an authenticated session.
    pub async fn get_alert(&self, session_token: &str, id: &str) -> Result<Alert, GatewayError> {
        self.execute_with_resource(
            "alerts.get",
            session_token,
            "read",
            "alert",
            Some(id),
            |session| async move { self.alerts.get_alert(&session.token, id).await },
        )
        .await
    }

    /// Modifies an alert for an authenticated session.
    pub async fn modify_alert(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAlertInput,
    ) -> Result<Alert, GatewayError> {
        self.execute_with_resource(
            "alerts.modify",
            session_token,
            "modify",
            "alert",
            Some(id),
            |session| async move { self.alerts.modify_alert(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes an alert for an authenticated session.
    pub async fn delete_alert(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "alerts.delete",
            session_token,
            "delete",
            "alert",
            Some(id),
            |session| async move { self.alerts.delete_alert(&session.token, id, ultimate).await },
        )
        .await
    }
}
