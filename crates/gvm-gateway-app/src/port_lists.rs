// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Port-list use cases.

use gvm_gateway_domain::{
    CreatePortListInput, GatewayError, ModifyPortListInput, PortList, PortListPage, PortListQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists port lists for an authenticated session.
    pub async fn list_port_lists(
        &self,
        session_token: &str,
        query: PortListQuery,
    ) -> Result<PortListPage, GatewayError> {
        self.execute_with_resource(
            "port_lists.list",
            session_token,
            "list",
            "port_list",
            None,
            |session| async move {
                self.port_lists
                    .list_port_lists(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Creates a new port list for an authenticated session.
    pub async fn create_port_list(
        &self,
        session_token: &str,
        input: CreatePortListInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "port_lists.create",
            session_token,
            "create",
            "port_list",
            None,
            |session| async move {
                self.port_lists
                    .create_port_list(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Fetches a port list for an authenticated session.
    pub async fn get_port_list(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<PortList, GatewayError> {
        self.execute_with_resource(
            "port_lists.get",
            session_token,
            "read",
            "port_list",
            Some(id),
            |session| async move { self.port_lists.get_port_list(&session.token, id).await },
        )
        .await
    }

    /// Modifies a port list for an authenticated session.
    pub async fn modify_port_list(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPortListInput,
    ) -> Result<PortList, GatewayError> {
        self.execute_with_resource(
            "port_lists.modify",
            session_token,
            "modify",
            "port_list",
            Some(id),
            |session| async move {
                self.port_lists
                    .modify_port_list(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a port list for an authenticated session.
    pub async fn delete_port_list(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "port_lists.delete",
            session_token,
            "delete",
            "port_list",
            Some(id),
            |session| async move { self.port_lists.delete_port_list(&session.token, id).await },
        )
        .await
    }
}
