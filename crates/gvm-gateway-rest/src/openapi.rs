// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OpenAPI generation helpers for the REST adapter.

use aide::{
    openapi::{License, SecurityScheme, Server, Tag},
    transform::{TransformOpenApi, TransformOperation, TransformResponse},
};
use axum::{
    extract::{Path, Query},
    Json,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn ok_json<T>(
    description: &'static str,
) -> impl FnOnce(TransformResponse<T>) -> TransformResponse<T> {
    move |response| response.description(description)
}

fn problem_response<'a, const N: u16>(
    op: TransformOperation<'a>,
    description: &'static str,
) -> TransformOperation<'a> {
    op.response_with::<N, Json<ProblemDetailDoc>, _>(|response| response.description(description))
}

/// Configure the top-level generated OpenAPI document.
pub(crate) fn configure(api: TransformOpenApi<'_>) -> TransformOpenApi<'_> {
    api.title("GVM REST API")
        .description("Generated OpenAPI for the currently implemented REST adapter surface.")
        .version(env!("CARGO_PKG_VERSION"))
        .license(License {
            name: "AGPL-3.0-or-later".to_string(),
            identifier: Some("AGPL-3.0-or-later".to_string()),
            url: None,
            extensions: Default::default(),
        })
        .server(Server {
            url: "/".to_string(),
            description: Some("Runtime-served REST endpoints".to_string()),
            variables: Default::default(),
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "System".to_string(),
            description: Some("System and health endpoints".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "Targets".to_string(),
            description: Some("Scan target management".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .security_scheme(
            "bearerAuth",
            SecurityScheme::Http {
                scheme: "bearer".to_string(),
                bearer_format: None,
                description: Some(
                    "Opaque session token returned by the session lifecycle API.".to_string(),
                ),
                extensions: Default::default(),
            },
        )
}

/// OpenAPI transform for `GET /health`.
pub(crate) fn health_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.id("getHealth")
        .tag("System")
        .summary("Liveness probe")
        .description("Returns basic process liveness information.")
        .response_with::<200, Json<HealthStatusDoc>, _>(ok_json("Service is alive"))
}

/// OpenAPI transform for `GET /ready`.
pub(crate) fn ready_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReadiness")
        .tag("System")
        .summary("Readiness probe")
        .description("Indicates whether the service is ready to handle requests.")
        .response_with::<200, Json<ReadinessStatusDoc>, _>(ok_json("Service is ready"))
        .response_with::<503, Json<ReadinessStatusDoc>, _>(ok_json("Service is not ready"));

    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/version`.
pub(crate) fn version_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getVersion")
        .tag("System")
        .summary("Get API and GMP version information")
        .description("Returns the gateway API version together with the connected GMP version.")
        .response_with::<200, Json<VersionInfoDoc>, _>(ok_json("Version information"));

    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/targets`.
pub(crate) fn list_targets_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTargets")
        .tag("Targets")
        .summary("List targets")
        .description("Returns a paginated list of targets.")
        .security_requirement("bearerAuth")
        .input::<Query<TargetListQueryDoc>>()
        .response_with::<200, Json<TargetListDoc>, _>(ok_json("Paginated list of targets"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/targets`.
pub(crate) fn create_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTarget")
        .tag("Targets")
        .summary("Create a target")
        .description("Creates a new scan target.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTargetDoc>>()
        .response_with::<201, Json<ResourceCreatedDoc>, _>(ok_json("Target created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/targets/{id}`.
pub(crate) fn get_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTarget")
        .tag("Targets")
        .summary("Get a target")
        .description("Returns the details for a single target.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TargetDoc>, _>(ok_json("Target details"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/targets/{id}`.
pub(crate) fn update_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTarget")
        .tag("Targets")
        .summary("Modify a target")
        .description("Updates an existing target.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTargetDoc>)>()
        .response_with::<200, Json<TargetDoc>, _>(ok_json("Target updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/targets/{id}`.
pub(crate) fn delete_target_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTarget")
        .tag("Targets")
        .summary("Delete a target")
        .description("Deletes an existing target.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Target deleted"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ProblemDetail")]
struct ProblemDetailDoc {
    #[serde(rename = "type")]
    r#type: String,
    title: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "HealthStatus")]
struct HealthStatusDoc {
    status: HealthStateDoc,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ReadinessStatus")]
struct ReadinessStatusDoc {
    status: ReadinessStateDoc,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "VersionInfo")]
struct VersionInfoDoc {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "Target")]
struct TargetDoc {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    hosts: Vec<String>,
    #[serde(
        rename = "excludeHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    exclude_hosts: Vec<String>,
    #[serde(rename = "aliveTest", skip_serializing_if = "Option::is_none")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portList", skip_serializing_if = "Option::is_none")]
    port_list: Option<ResourceRefDoc>,
    #[serde(rename = "reverseLookupOnly")]
    reverse_lookup_only: bool,
    #[serde(rename = "reverseLookupUnify")]
    reverse_lookup_unify: bool,
    #[serde(rename = "sshCredential", skip_serializing_if = "Option::is_none")]
    ssh_credential: Option<ResourceRefDoc>,
    #[serde(rename = "smbCredential", skip_serializing_if = "Option::is_none")]
    smb_credential: Option<ResourceRefDoc>,
    #[serde(rename = "esxiCredential", skip_serializing_if = "Option::is_none")]
    esxi_credential: Option<ResourceRefDoc>,
    #[serde(rename = "snmpCredential", skip_serializing_if = "Option::is_none")]
    snmp_credential: Option<ResourceRefDoc>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "TargetList")]
struct TargetListDoc {
    data: Vec<TargetDoc>,
    pagination: PaginationDoc,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "Pagination")]
struct PaginationDoc {
    page: u32,
    #[serde(rename = "perPage")]
    per_page: u32,
    total: u32,
    #[serde(rename = "totalPages")]
    total_pages: u32,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTarget")]
struct CreateTargetDoc {
    name: String,
    comment: Option<String>,
    hosts: Vec<String>,
    #[serde(rename = "excludeHosts", default)]
    exclude_hosts: Vec<String>,
    #[serde(rename = "aliveTest")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portListId")]
    port_list_id: Option<Uuid>,
    #[serde(rename = "reverseLookupOnly")]
    reverse_lookup_only: Option<bool>,
    #[serde(rename = "reverseLookupUnify")]
    reverse_lookup_unify: Option<bool>,
    #[serde(rename = "sshCredentialId")]
    ssh_credential_id: Option<Uuid>,
    #[serde(rename = "smbCredentialId")]
    smb_credential_id: Option<Uuid>,
    #[serde(rename = "esxiCredentialId")]
    esxi_credential_id: Option<Uuid>,
    #[serde(rename = "snmpCredentialId")]
    snmp_credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyTarget")]
struct ModifyTargetDoc {
    name: Option<String>,
    comment: Option<String>,
    hosts: Option<Vec<String>>,
    #[serde(rename = "excludeHosts")]
    exclude_hosts: Option<Vec<String>>,
    #[serde(rename = "aliveTest")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portListId")]
    port_list_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ResourceCreated")]
struct ResourceCreatedDoc {
    id: Uuid,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ResourceRef")]
struct ResourceRefDoc {
    id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct TargetListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct ResourceIdPathDoc {
    id: Uuid,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum HealthStateDoc {
    #[serde(rename = "ok")]
    Ok,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum ReadinessStateDoc {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "notReady")]
    NotReady,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum AliveTestDoc {
    #[serde(rename = "Scan Config Default")]
    ScanConfigDefault,
    #[serde(rename = "ICMP Ping")]
    IcmpPing,
    #[serde(rename = "TCP-ACK Service Ping")]
    TcpAckServicePing,
    #[serde(rename = "TCP-SYN Service Ping")]
    TcpSynServicePing,
    #[serde(rename = "ARP Ping")]
    ArpPing,
    #[serde(rename = "ICMP, TCP-ACK Service Ping")]
    IcmpTcpAckServicePing,
    #[serde(rename = "ICMP, ARP Ping")]
    IcmpArpPing,
    #[serde(rename = "TCP-ACK Service, ARP Ping")]
    TcpAckServiceArpPing,
    #[serde(rename = "ICMP, TCP-ACK Service, ARP Ping")]
    IcmpTcpAckServiceArpPing,
    #[serde(rename = "Consider Alive")]
    ConsiderAlive,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use async_trait::async_trait;
    use serde_json::Value;

    use crate::router::build_openapi;
    use gvm_gateway_domain::{
        CreateTargetInput, GatewayError, ModifyTargetInput, ReadinessStatus, SystemPort, Target,
        TargetPage, TargetPort, TargetQuery,
    };

    struct StubSystem;
    struct StubTarget;

    impl SystemPort for StubSystem {
        fn readiness(&self) -> Result<ReadinessStatus, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        fn gmp_version(&self) -> Result<String, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }
    }

    #[async_trait]
    impl TargetPort for StubTarget {
        async fn list_targets(&self, _: &str, _: &TargetQuery) -> Result<TargetPage, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn create_target(
            &self,
            _: &str,
            _: CreateTargetInput,
        ) -> Result<String, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn get_target(&self, _: &str, _: &str) -> Result<Target, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn modify_target(
            &self,
            _: &str,
            _: &str,
            _: ModifyTargetInput,
        ) -> Result<Target, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn delete_target(&self, _: &str, _: &str) -> Result<(), GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }
    }

    #[test]
    fn generated_openapi_subset_matches_curated_spec() {
        let generated = serde_json::to_value(build_openapi::<StubSystem, StubTarget>()).unwrap();
        let system_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/system.yaml")).unwrap();
        let targets_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();

        let checks = [
            ("/health", "get", &system_spec, "/health", &["200"] as &[_]),
            ("/ready", "get", &system_spec, "/ready", &["200", "503"]),
            (
                "/api/v1/version",
                "get",
                &system_spec,
                "/version",
                &["200", "502"],
            ),
            (
                "/api/v1/targets",
                "get",
                &targets_spec,
                "/targets",
                &["200", "400", "401"],
            ),
            (
                "/api/v1/targets",
                "post",
                &targets_spec,
                "/targets",
                &["201", "400", "401"],
            ),
            (
                "/api/v1/targets/{id}",
                "get",
                &targets_spec,
                "/targets/{id}",
                &["200", "400", "401", "404"],
            ),
            (
                "/api/v1/targets/{id}",
                "put",
                &targets_spec,
                "/targets/{id}",
                &["200", "400", "401", "404"],
            ),
            (
                "/api/v1/targets/{id}",
                "delete",
                &targets_spec,
                "/targets/{id}",
                &["204", "400", "401", "404"],
            ),
        ];

        for (generated_path, method, curated_doc, curated_path, statuses) in checks {
            let generated_op = op(&generated, generated_path, method);
            let curated_op = op(curated_doc, curated_path, method);

            assert_eq!(
                generated_op["operationId"], curated_op["operationId"],
                "operationId drift for {method} {generated_path}"
            );

            let generated_statuses = response_statuses(generated_op);
            for status in statuses {
                assert!(
                    generated_statuses.contains(status),
                    "missing generated status {status} for {method} {generated_path}"
                );
            }
        }
    }

    #[test]
    fn generated_openapi_preserves_key_schema_fields() {
        let generated = serde_json::to_value(build_openapi::<StubSystem, StubTarget>()).unwrap();

        let target_props = &generated["components"]["schemas"]["Target"]["properties"];
        assert!(target_props.get("excludeHosts").is_some());
        assert!(target_props.get("aliveTest").is_some());
        assert!(target_props.get("portList").is_some());
        assert_eq!(target_props["id"]["format"], "uuid");

        let pagination_props = &generated["components"]["schemas"]["Pagination"]["properties"];
        assert!(pagination_props.get("perPage").is_some());
        assert!(pagination_props.get("totalPages").is_some());

        let create_target_required = generated["components"]["schemas"]["CreateTarget"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert!(create_target_required.contains("name"));
        assert!(create_target_required.contains("hosts"));
    }

    fn op<'a>(doc: &'a Value, path: &str, method: &str) -> &'a Value {
        &doc["paths"][path][method]
    }

    fn response_statuses(operation: &Value) -> BTreeSet<&str> {
        operation["responses"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }
}
