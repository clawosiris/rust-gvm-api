// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

use gvm_client::AgentInstallerLanguage;
use gvm_gateway_domain::{
    Agent, AgentConfig, AgentControlConfig, AgentGroup, AgentGroupPage, AgentGroupQuery,
    AgentInstallerInstruction, AgentInstallerInstructionQuery, AgentPage, AgentPort, AgentQuery,
    AgentRetryConfig, AgentScriptExecutorConfig, AgentSupportBundle, AgentSupportBundleQuery,
    CreateAgentGroupInput, GatewayError, ModifyAgentControlScanConfigInput, ModifyAgentGroupInput,
    ModifyAgentInput,
};
use gvm_gmp::{
    commands::{
        agent_groups::{GetAgentGroupsOpts, ModifyAgentGroupOpts},
        agents::{
            AgentConfigOpts, AgentControlConfig as GmpAgentControlConfig,
            AgentHeartbeatConfig as GmpAgentHeartbeatConfig,
            AgentRetryConfig as GmpAgentRetryConfig,
            AgentScriptExecutorConfig as GmpAgentScriptExecutorConfig, GetAgentsOpts,
            ModifyAgentControlScanConfigOpts, ModifyAgentOpts,
        },
    },
    responses::{
        CreateAgentGroupResponse, GetAgentGroupsResponse, GetAgentInstallerInstructionResponse,
        GetAgentSupportBundleResponse, GetAgentsResponse,
    },
    EntityId,
};

use crate::conversions::{
    agent_from_gmp, agent_group_from_gmp, agent_installer_instruction_from_gmp,
    agent_support_bundle_from_gmp, map_parse_error, parse_entity_id,
};

const MAX_AGENT_SUPPORT_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[async_trait]
impl AgentPort for GvmdAdapter {
    async fn list_agents(
        &self,
        session_token: &str,
        query: &AgentQuery,
    ) -> Result<AgentPage, GatewayError> {
        let filter_id = parse_optional_filter_id(query.filter_id.as_deref())?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;

        let response = self
            .call_with_session(
                session_token,
                "agents.list",
                gvm_gmp::commands::agents::get_agents(GetAgentsOpts {
                    filter_string,
                    filter_id: None,
                }),
            )
            .await?;
        let parsed = GetAgentsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(agent_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        if needs_client_side_pagination_fallback(&items, total, query.page) {
            let response = self
                .call_with_session(
                    session_token,
                    "agents.list",
                    gvm_gmp::commands::agents::get_agents(GetAgentsOpts {
                        filter_string: self
                            .filter_resolving_filter_id(
                                session_token,
                                None,
                                query.filter_string.as_deref(),
                                filter_id.as_ref(),
                                &[],
                            )
                            .await?,
                        filter_id: None,
                    }),
                )
                .await?;
            let parsed = GetAgentsResponse::from_response(&response).map_err(map_parse_error)?;
            let items = parsed
                .items
                .into_iter()
                .map(agent_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
            return Ok(AgentPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(AgentPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_agent(&self, session_token: &str, id: &str) -> Result<Agent, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agents.get",
                gvm_gmp::commands::agents::get_agent(&parse_entity_id(id)?),
            )
            .await?;
        GetAgentsResponse::from_response(&response)
            .map_err(map_parse_error)?
            .items
            .into_iter()
            .next()
            .map(agent_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("agent {id} not found")))
    }

    async fn modify_agent(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentInput,
    ) -> Result<Agent, GatewayError> {
        let agent_id = parse_entity_id(id)?;
        let response = self
            .call_with_session(
                session_token,
                "agents.modify",
                gvm_gmp::commands::agents::modify_agent(
                    std::slice::from_ref(&agent_id),
                    modify_agent_opts_from_input(input),
                ),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_agent(session_token, id).await
    }

    async fn delete_agent(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let agent_id = parse_entity_id(id)?;
        let response = self
            .call_with_session(
                session_token,
                "agents.delete",
                gvm_gmp::commands::agents::delete_agent(std::slice::from_ref(&agent_id)),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn sync_agents(&self, session_token: &str) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agents.sync",
                gvm_gmp::commands::agents::sync_agents(),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn get_agent_support_bundle(
        &self,
        session_token: &str,
        id: &str,
        query: &AgentSupportBundleQuery,
    ) -> Result<AgentSupportBundle, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agents.support_bundle",
                gvm_gmp::commands::agents::get_agent_support_bundle(
                    &parse_entity_id(id)?,
                    query.days,
                ),
            )
            .await?;
        let parsed =
            GetAgentSupportBundleResponse::from_response(&response).map_err(map_parse_error)?;
        let bundle = agent_support_bundle_from_gmp(parsed);
        if bundle.artifact.bytes.len() > MAX_AGENT_SUPPORT_BUNDLE_BYTES {
            return Err(GatewayError::BackendUnavailable(format!(
                "agent support bundle exceeds the {} byte gateway limit",
                MAX_AGENT_SUPPORT_BUNDLE_BYTES
            )));
        }
        Ok(bundle)
    }

    async fn modify_agent_control_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentControlScanConfigInput,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agents.control_scan_config.modify",
                gvm_gmp::commands::agents::modify_agent_control_scan_config(
                    &parse_entity_id(id)?,
                    ModifyAgentControlScanConfigOpts {
                        agent_defaults: input.agent_defaults.map(agent_config_opts_from_domain),
                        update_to_latest: input.update_to_latest,
                    },
                ),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn get_agent_installer_instruction(
        &self,
        session_token: &str,
        scanner_id: &str,
        query: &AgentInstallerInstructionQuery,
    ) -> Result<AgentInstallerInstruction, GatewayError> {
        let language = parse_agent_installer_language(&query.language)?;
        let response = self
            .call_with_session(
                session_token,
                "agents.installer_instruction.get",
                gvm_gmp::commands::agents::get_agent_installer_instruction(
                    &parse_entity_id(scanner_id)?,
                    language,
                    &query.origin_url,
                ),
            )
            .await?;
        let parsed = GetAgentInstallerInstructionResponse::from_response(&response)
            .map_err(map_parse_error)?;
        Ok(agent_installer_instruction_from_gmp(parsed))
    }

    async fn list_agent_groups(
        &self,
        session_token: &str,
        query: &AgentGroupQuery,
    ) -> Result<AgentGroupPage, GatewayError> {
        let filter_id = parse_optional_filter_id(query.filter_id.as_deref())?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;

        let response = self
            .call_with_session(
                session_token,
                "agent_groups.list",
                gvm_gmp::commands::agent_groups::get_agent_groups(GetAgentGroupsOpts {
                    filter_string,
                    filter_id: None,
                    trash: Some(query.trash),
                }),
            )
            .await?;
        let parsed = GetAgentGroupsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(agent_group_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        if needs_client_side_pagination_fallback(&items, total, query.page) {
            let response = self
                .call_with_session(
                    session_token,
                    "agent_groups.list",
                    gvm_gmp::commands::agent_groups::get_agent_groups(GetAgentGroupsOpts {
                        filter_string: self
                            .filter_resolving_filter_id(
                                session_token,
                                None,
                                query.filter_string.as_deref(),
                                filter_id.as_ref(),
                                &[],
                            )
                            .await?,
                        filter_id: None,
                        trash: Some(query.trash),
                    }),
                )
                .await?;
            let parsed =
                GetAgentGroupsResponse::from_response(&response).map_err(map_parse_error)?;
            let items = parsed
                .items
                .into_iter()
                .map(agent_group_from_gmp)
                .collect::<Vec<_>>();
            let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
            return Ok(AgentGroupPage {
                data: paged_slice(items, query.page, query.per_page),
                pagination: paged_pagination(total, query.page, query.per_page),
            });
        }

        Ok(AgentGroupPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_agent_group(
        &self,
        session_token: &str,
        input: CreateAgentGroupInput,
    ) -> Result<String, GatewayError> {
        let agent_ids = parse_entity_ids(&input.agent_ids)?;
        let response = self
            .call_with_session(
                session_token,
                "agent_groups.create",
                gvm_gmp::commands::agent_groups::create_agent_group(
                    &input.name,
                    &agent_ids,
                    &input.scheduler_cron_time,
                    gvm_client::CreateAgentGroupOpts {
                        comment: input.comment,
                    },
                ),
            )
            .await?;
        Ok(CreateAgentGroupResponse::from_response(&response)
            .map_err(map_parse_error)?
            .id
            .to_string())
    }

    async fn get_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<AgentGroup, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agent_groups.get",
                gvm_gmp::commands::agent_groups::get_agent_group(&parse_entity_id(id)?),
            )
            .await?;
        GetAgentGroupsResponse::from_response(&response)
            .map_err(map_parse_error)?
            .items
            .into_iter()
            .next()
            .map(agent_group_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("agent group {id} not found")))
    }

    async fn modify_agent_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyAgentGroupInput,
    ) -> Result<AgentGroup, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agent_groups.modify",
                gvm_gmp::commands::agent_groups::modify_agent_group(
                    &parse_entity_id(id)?,
                    &input.scheduler_cron_time,
                    ModifyAgentGroupOpts {
                        name: input.name,
                        comment: input.comment,
                        agent_ids: input
                            .agent_ids
                            .as_deref()
                            .map(parse_entity_ids)
                            .transpose()?
                            .unwrap_or_default(),
                    },
                ),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        self.get_agent_group(session_token, id).await
    }

    async fn delete_agent_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agent_groups.delete",
                gvm_gmp::commands::agent_groups::delete_agent_group(
                    &parse_entity_id(id)?,
                    ultimate,
                ),
            )
            .await?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn clone_agent_group(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        let response = self
            .call_with_session(
                session_token,
                "agent_groups.clone",
                gvm_gmp::commands::agent_groups::clone_agent_group(&parse_entity_id(id)?),
            )
            .await?;
        Ok(CreateAgentGroupResponse::from_response(&response)
            .map_err(map_parse_error)?
            .id
            .to_string())
    }
}

fn parse_optional_filter_id(value: Option<&str>) -> Result<Option<EntityId>, GatewayError> {
    value
        .map(|value| {
            EntityId::new(value)
                .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
        })
        .transpose()
}

fn parse_entity_ids(ids: &[String]) -> Result<Vec<EntityId>, GatewayError> {
    ids.iter().map(|id| parse_entity_id(id)).collect()
}

fn parse_agent_installer_language(value: &str) -> Result<AgentInstallerLanguage, GatewayError> {
    match value {
        "en" => Ok(AgentInstallerLanguage::En),
        "de" => Ok(AgentInstallerLanguage::De),
        _ => Err(GatewayError::InvalidInput(
            "language must be one of: en, de".to_string(),
        )),
    }
}

fn modify_agent_opts_from_input(input: ModifyAgentInput) -> ModifyAgentOpts {
    ModifyAgentOpts {
        authorized: input.authorized,
        update_to_latest: input.update_to_latest,
        comment: input.comment,
        config: input.config.map(agent_config_opts_from_domain),
    }
}

fn agent_config_opts_from_domain(input: AgentConfig) -> AgentConfigOpts {
    AgentConfigOpts {
        agent_control: input
            .agent_control
            .map(agent_control_config_opts_from_domain),
        agent_script_executor: input
            .agent_script_executor
            .map(agent_script_executor_config_opts_from_domain),
        heartbeat: input.heartbeat.map(agent_heartbeat_config_opts_from_domain),
    }
}

fn agent_control_config_opts_from_domain(input: AgentControlConfig) -> GmpAgentControlConfig {
    GmpAgentControlConfig {
        retry: input.retry.map(agent_retry_config_opts_from_domain),
    }
}

fn agent_retry_config_opts_from_domain(input: AgentRetryConfig) -> GmpAgentRetryConfig {
    GmpAgentRetryConfig {
        attempts: input.attempts,
        delay_in_seconds: input.delay_in_seconds,
        max_jitter_in_seconds: input.max_jitter_in_seconds,
    }
}

fn agent_script_executor_config_opts_from_domain(
    input: AgentScriptExecutorConfig,
) -> GmpAgentScriptExecutorConfig {
    GmpAgentScriptExecutorConfig {
        bulk_size: input.bulk_size,
        bulk_throttle_time_in_ms: input.bulk_throttle_time_in_ms,
        indexer_dir_depth: input.indexer_dir_depth,
        scheduler_cron_time: input.scheduler_cron_time,
    }
}

fn agent_heartbeat_config_opts_from_domain(
    input: gvm_gateway_domain::AgentHeartbeatConfig,
) -> GmpAgentHeartbeatConfig {
    GmpAgentHeartbeatConfig {
        interval_in_seconds: input.interval_in_seconds,
        miss_until_inactive: input.miss_until_inactive,
    }
}
