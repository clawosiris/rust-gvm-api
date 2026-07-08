// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST contract placeholders for current-GVMD resource families whose request
//! builders exist in `rust-gvm` devel before typed response models do.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;

use crate::{error::RestError, openapi::problem_response, router::bearer_token};

const DETAIL: &str = "This route is reserved for the current GVMD typed surface, but rust-gvm does not yet provide the typed response model required by rust-gvm-api's no-raw-GMP-XML policy.";

/// Shared handler for intentionally reserved current-GVMD routes.
pub async fn not_implemented(
    State(_service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let instance = uri.path().to_string();
    if let Err(error) = bearer_token(&headers) {
        return RestError::from_gateway_error(error, instance).into_response();
    }

    RestError::from_gateway_error(GatewayError::NotImplemented(DETAIL.to_string()), instance)
        .into_response()
}

fn reserved_docs<'a>(
    op: TransformOperation<'a>,
    operation_id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    let op = op
        .id(operation_id)
        .tag(tag)
        .summary(summary)
        .description(DETAIL)
        .security_requirement("bearerAuth");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<501>(op, "Typed upstream response support is not implemented yet")
}

macro_rules! reserved_doc {
    ($name:ident, $operation_id:literal, $tag:literal, $summary:literal) => {
        /// OpenAPI transform for a reserved current-GVMD route.
        pub(crate) fn $name(op: TransformOperation<'_>) -> TransformOperation<'_> {
            reserved_docs(op, $operation_id, $tag, $summary)
        }
    };
}

reserved_doc!(list_agents_docs, "getAgents", "Agents", "List agents");
reserved_doc!(get_agent_docs, "getAgent", "Agents", "Get an agent");
reserved_doc!(modify_agent_docs, "modifyAgent", "Agents", "Modify agents");
reserved_doc!(delete_agent_docs, "deleteAgent", "Agents", "Delete agents");
reserved_doc!(
    sync_agents_docs,
    "syncAgents",
    "Agents",
    "Synchronize agents"
);
reserved_doc!(
    get_agent_support_bundle_docs,
    "getAgentSupportBundle",
    "Agents",
    "Get an agent support bundle"
);
reserved_doc!(
    modify_agent_control_scan_config_docs,
    "modifyAgentControlScanConfig",
    "Agents",
    "Modify agent-control scan config defaults"
);
reserved_doc!(
    get_agent_installer_instruction_docs,
    "getAgentInstallerInstruction",
    "Agents",
    "Get agent installer instructions"
);

reserved_doc!(
    list_agent_groups_docs,
    "getAgentGroups",
    "Agent Groups",
    "List agent groups"
);
reserved_doc!(
    create_agent_group_docs,
    "createAgentGroup",
    "Agent Groups",
    "Create an agent group"
);
reserved_doc!(
    get_agent_group_docs,
    "getAgentGroup",
    "Agent Groups",
    "Get an agent group"
);
reserved_doc!(
    modify_agent_group_docs,
    "modifyAgentGroup",
    "Agent Groups",
    "Modify an agent group"
);
reserved_doc!(
    delete_agent_group_docs,
    "deleteAgentGroup",
    "Agent Groups",
    "Delete an agent group"
);
reserved_doc!(
    clone_agent_group_docs,
    "cloneAgentGroup",
    "Agent Groups",
    "Clone an agent group"
);

reserved_doc!(
    list_assets_docs,
    "getAssets",
    "Assets",
    "List generic assets"
);
reserved_doc!(
    create_asset_docs,
    "createAsset",
    "Assets",
    "Create a generic asset"
);
reserved_doc!(get_asset_docs, "getAsset", "Assets", "Get a generic asset");
reserved_doc!(
    modify_asset_docs,
    "modifyAsset",
    "Assets",
    "Modify a generic asset"
);
reserved_doc!(
    delete_asset_docs,
    "deleteAsset",
    "Assets",
    "Delete a generic asset"
);

reserved_doc!(
    list_configs_docs,
    "getConfigs",
    "Configs",
    "List generic configs"
);
reserved_doc!(
    create_config_docs,
    "createConfig",
    "Configs",
    "Create a generic config"
);
reserved_doc!(
    get_config_docs,
    "getConfig",
    "Configs",
    "Get a generic config"
);
reserved_doc!(
    modify_config_docs,
    "modifyConfig",
    "Configs",
    "Modify a generic config"
);
reserved_doc!(
    delete_config_docs,
    "deleteConfig",
    "Configs",
    "Delete a generic config"
);
reserved_doc!(
    clone_config_docs,
    "cloneConfig",
    "Configs",
    "Clone a generic config"
);

reserved_doc!(
    list_oci_image_targets_docs,
    "getOciImageTargets",
    "OCI Image Targets",
    "List OCI image targets"
);
reserved_doc!(
    create_oci_image_target_docs,
    "createOciImageTarget",
    "OCI Image Targets",
    "Create an OCI image target"
);
reserved_doc!(
    get_oci_image_target_docs,
    "getOciImageTarget",
    "OCI Image Targets",
    "Get an OCI image target"
);
reserved_doc!(
    modify_oci_image_target_docs,
    "modifyOciImageTarget",
    "OCI Image Targets",
    "Modify an OCI image target"
);
reserved_doc!(
    delete_oci_image_target_docs,
    "deleteOciImageTarget",
    "OCI Image Targets",
    "Delete an OCI image target"
);
reserved_doc!(
    clone_oci_image_target_docs,
    "cloneOciImageTarget",
    "OCI Image Targets",
    "Clone an OCI image target"
);

reserved_doc!(
    list_web_application_targets_docs,
    "getWebApplicationTargets",
    "Web Application Targets",
    "List web application targets"
);
reserved_doc!(
    create_web_application_target_docs,
    "createWebApplicationTarget",
    "Web Application Targets",
    "Create a web application target"
);
reserved_doc!(
    get_web_application_target_docs,
    "getWebApplicationTarget",
    "Web Application Targets",
    "Get a web application target"
);
reserved_doc!(
    modify_web_application_target_docs,
    "modifyWebApplicationTarget",
    "Web Application Targets",
    "Modify a web application target"
);
reserved_doc!(
    delete_web_application_target_docs,
    "deleteWebApplicationTarget",
    "Web Application Targets",
    "Delete a web application target"
);
reserved_doc!(
    clone_web_application_target_docs,
    "cloneWebApplicationTarget",
    "Web Application Targets",
    "Clone a web application target"
);

reserved_doc!(
    get_report_hosts_docs,
    "getReportHosts",
    "Reports",
    "Get report hosts"
);
reserved_doc!(
    get_report_ports_docs,
    "getReportPorts",
    "Reports",
    "Get report ports"
);
reserved_doc!(
    get_report_applications_docs,
    "getReportApplications",
    "Reports",
    "Get report applications"
);
reserved_doc!(
    get_report_operating_systems_docs,
    "getReportOperatingSystems",
    "Reports",
    "Get report operating systems"
);
reserved_doc!(
    get_report_cves_docs,
    "getReportCves",
    "Reports",
    "Get report CVEs"
);

reserved_doc!(
    list_operating_systems_docs,
    "getOperatingSystems",
    "Operating Systems",
    "List operating systems"
);
reserved_doc!(
    get_operating_system_docs,
    "getOperatingSystem",
    "Operating Systems",
    "Get an operating system"
);
reserved_doc!(
    modify_operating_system_docs,
    "modifyOperatingSystem",
    "Operating Systems",
    "Modify an operating system"
);
reserved_doc!(
    delete_operating_system_docs,
    "deleteOperatingSystem",
    "Operating Systems",
    "Delete an operating system"
);
