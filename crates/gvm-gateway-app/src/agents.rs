// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Agent and agent-group use cases.

use gvm_gateway_domain::{
    Agent, AgentGroup, AgentGroupPage, AgentGroupQuery, AgentInstallerInstruction,
    AgentInstallerInstructionQuery, AgentPage, AgentQuery, AgentSupportBundle,
    AgentSupportBundleQuery, CreateAgentGroupInput, GatewayError,
    ModifyAgentControlScanConfigInput, ModifyAgentGroupInput, ModifyAgentInput,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists agents for an authenticated session.
    pub async fn list_agents(
        &self,
        session_token: &str,
        query: AgentQuery,
    ) -> Result<AgentPage, GatewayError> {
        self.execute_with_resource(
            "agents.list",
            session_token,
            "list",
            "agent",
            None,
            |session| async move { self.agents.list_agents(&session.token, &query).await },
        )
        .await
    }

    /// Fetches an agent for an authenticated session.
    pub async fn get_agent(&self, session_token: &str, id: &str) -> Result<Agent, GatewayError> {
        self.execute_with_resource(
            "agents.get",
            session_token,
            "read",
            "agent",
            Some(id),
            |session| async move { self.agents.get_agent(&session.token, id).await },
        )
        .await
    }

    /// Modifies an agent for an authenticated session.
    pub async fn modify_agent(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentInput,
    ) -> Result<Agent, GatewayError> {
        self.execute_with_resource(
            "agents.modify",
            session_token,
            "modify",
            "agent",
            Some(id),
            |session| async move { self.agents.modify_agent(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes an agent for an authenticated session.
    pub async fn delete_agent(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "agents.delete",
            session_token,
            "delete",
            "agent",
            Some(id),
            |session| async move { self.agents.delete_agent(&session.token, id).await },
        )
        .await
    }

    /// Synchronizes agents for an authenticated session.
    pub async fn sync_agents(&self, session_token: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "agents.sync",
            session_token,
            "sync",
            "agent",
            None,
            |session| async move { self.agents.sync_agents(&session.token).await },
        )
        .await
    }

    /// Downloads an agent support bundle for an authenticated session.
    pub async fn get_agent_support_bundle(
        &self,
        session_token: &str,
        id: &str,
        query: AgentSupportBundleQuery,
    ) -> Result<AgentSupportBundle, GatewayError> {
        self.execute_with_resource(
            "agents.support_bundle",
            session_token,
            "read",
            "agent_support_bundle",
            Some(id),
            |session| async move {
                self.agents
                    .get_agent_support_bundle(&session.token, id, &query)
                    .await
            },
        )
        .await
    }

    /// Modifies agent-control scan-config defaults for an authenticated session.
    pub async fn modify_agent_control_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentControlScanConfigInput,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "agents.control_scan_config.modify",
            session_token,
            "modify",
            "agent_control_scan_config",
            Some(id),
            |session| async move {
                self.agents
                    .modify_agent_control_scan_config(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Fetches agent installer instructions for an authenticated session.
    pub async fn get_agent_installer_instruction(
        &self,
        session_token: &str,
        scanner_id: &str,
        query: AgentInstallerInstructionQuery,
    ) -> Result<AgentInstallerInstruction, GatewayError> {
        self.execute_with_resource(
            "agents.installer_instruction.get",
            session_token,
            "read",
            "agent_installer_instruction",
            Some(scanner_id),
            |session| async move {
                self.agents
                    .get_agent_installer_instruction(&session.token, scanner_id, &query)
                    .await
            },
        )
        .await
    }

    /// Lists agent groups for an authenticated session.
    pub async fn list_agent_groups(
        &self,
        session_token: &str,
        query: AgentGroupQuery,
    ) -> Result<AgentGroupPage, GatewayError> {
        self.execute_with_resource(
            "agent_groups.list",
            session_token,
            "list",
            "agent_group",
            None,
            |session| async move { self.agents.list_agent_groups(&session.token, &query).await },
        )
        .await
    }

    /// Creates an agent group for an authenticated session.
    pub async fn create_agent_group(
        &self,
        session_token: &str,
        input: CreateAgentGroupInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "agent_groups.create",
            session_token,
            "create",
            "agent_group",
            None,
            |session| async move { self.agents.create_agent_group(&session.token, input).await },
        )
        .await
    }

    /// Fetches an agent group for an authenticated session.
    pub async fn get_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<AgentGroup, GatewayError> {
        self.execute_with_resource(
            "agent_groups.get",
            session_token,
            "read",
            "agent_group",
            Some(id),
            |session| async move { self.agents.get_agent_group(&session.token, id).await },
        )
        .await
    }

    /// Modifies an agent group for an authenticated session.
    pub async fn modify_agent_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentGroupInput,
    ) -> Result<AgentGroup, GatewayError> {
        self.execute_with_resource(
            "agent_groups.modify",
            session_token,
            "modify",
            "agent_group",
            Some(id),
            |session| async move {
                self.agents
                    .modify_agent_group(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes an agent group for an authenticated session.
    pub async fn delete_agent_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "agent_groups.delete",
            session_token,
            "delete",
            "agent_group",
            Some(id),
            |session| async move {
                self.agents
                    .delete_agent_group(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Clones an agent group for an authenticated session.
    pub async fn clone_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "agent_groups.clone",
            session_token,
            "create",
            "agent_group",
            Some(id),
            |session| async move { self.agents.clone_agent_group(&session.token, id).await },
        )
        .await
    }
}
