// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! REST contract placeholders for current-GVMD resource families whose request
//! builders exist in `rust-gvm` devel before typed response models do.

use aide::transform::TransformOperation;
use axum::{
    extract::{OriginalUri, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::GatewayError;

use crate::{
    error::RestError,
    openapi::{problem_response, ResourceIdPathDoc},
    router::bearer_token,
};

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

fn reserved_id_docs<'a>(
    op: TransformOperation<'a>,
    operation_id: &'static str,
    tag: &'static str,
    summary: &'static str,
) -> TransformOperation<'a> {
    reserved_docs(op, operation_id, tag, summary).input::<Path<ResourceIdPathDoc>>()
}

macro_rules! reserved_doc {
    ($name:ident, $operation_id:literal, $tag:literal, $summary:literal) => {
        /// OpenAPI transform for a reserved current-GVMD route.
        pub(crate) fn $name(op: TransformOperation<'_>) -> TransformOperation<'_> {
            reserved_docs(op, $operation_id, $tag, $summary)
        }
    };
}

macro_rules! reserved_id_doc {
    ($name:ident, $operation_id:literal, $tag:literal, $summary:literal) => {
        /// OpenAPI transform for a reserved current-GVMD route with a resource id.
        pub(crate) fn $name(op: TransformOperation<'_>) -> TransformOperation<'_> {
            reserved_id_docs(op, $operation_id, $tag, $summary)
        }
    };
}

reserved_id_doc!(
    get_report_hosts_docs,
    "getReportHosts",
    "Reports",
    "Get report hosts"
);
reserved_id_doc!(
    get_report_ports_docs,
    "getReportPorts",
    "Reports",
    "Get report ports"
);
reserved_id_doc!(
    get_report_applications_docs,
    "getReportApplications",
    "Reports",
    "Get report applications"
);
reserved_id_doc!(
    get_report_operating_systems_docs,
    "getReportOperatingSystems",
    "Reports",
    "Get report operating systems"
);
reserved_id_doc!(
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
reserved_id_doc!(
    get_operating_system_docs,
    "getOperatingSystem",
    "Operating Systems",
    "Get an operating system"
);
reserved_id_doc!(
    modify_operating_system_docs,
    "modifyOperatingSystem",
    "Operating Systems",
    "Modify an operating system"
);
reserved_id_doc!(
    delete_operating_system_docs,
    "deleteOperatingSystem",
    "Operating Systems",
    "Delete an operating system"
);
