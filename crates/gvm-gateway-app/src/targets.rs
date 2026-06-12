// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Target use cases.

use gvm_gateway_domain::{
    CreateTargetInput, GatewayError, ModifyTargetInput, Target, TargetPage, TargetQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists targets for an authenticated session.
    pub async fn list_targets(
        &self,
        session_token: &str,
        query: TargetQuery,
    ) -> Result<TargetPage, GatewayError> {
        self.execute_with_resource(
            "targets.list",
            session_token,
            "list",
            "target",
            None,
            |session| async move { self.targets.list_targets(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new target for an authenticated session.
    pub async fn create_target(
        &self,
        session_token: &str,
        input: CreateTargetInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "targets.create",
            session_token,
            "create",
            "target",
            None,
            |session| async move { self.targets.create_target(&session.token, input).await },
        )
        .await
    }

    /// Fetches a target for an authenticated session.
    pub async fn get_target(&self, session_token: &str, id: &str) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.get",
            session_token,
            "read",
            "target",
            Some(id),
            |session| async move { self.targets.get_target(&session.token, id).await },
        )
        .await
    }

    /// Modifies a target for an authenticated session.
    pub async fn modify_target(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTargetInput,
    ) -> Result<Target, GatewayError> {
        self.execute_with_resource(
            "targets.modify",
            session_token,
            "modify",
            "target",
            Some(id),
            |session| async move { self.targets.modify_target(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a target for an authenticated session.
    pub async fn delete_target(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "targets.delete",
            session_token,
            "delete",
            "target",
            Some(id),
            |session| async move {
                self.targets
                    .delete_target(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }
}
