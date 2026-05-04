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
use serde_json::{json, Map, Value};
use uuid::Uuid;

fn datetime_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "format": "date-time"
    })
}

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

/// Finalize the generated OpenAPI document so its served contract shape matches
/// the curated repository spec for the implemented subset.
pub(crate) fn finalize_document(mut document: Value) -> Value {
    document["servers"] = json!([
        {
            "url": "/api/v1",
            "description": "Base path for all API endpoints"
        }
    ]);
    document["security"] = json!([
        {
            "bearerAuth": []
        }
    ]);
    document["tags"] = json!([
        {
            "name": "Sessions",
            "description": "Session lifecycle"
        },
        {
            "name": "Targets",
            "description": "Scan target management"
        },
        {
            "name": "Scan Configs",
            "description": "Scan configuration management"
        },
        {
            "name": "Scanners",
            "description": "Scanner management"
        },
        {
            "name": "System",
            "description": "System and health endpoints"
        }
    ]);

    let source_paths = document["paths"].as_object().cloned().unwrap_or_default();
    let mut normalized_paths = Map::new();

    copy_path(&source_paths, &mut normalized_paths, "/health", "/health");
    copy_path(&source_paths, &mut normalized_paths, "/ready", "/ready");
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/version",
        "/version",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/sessions",
        "/sessions",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/sessions/{token}",
        "/sessions/{token}",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/targets",
        "/targets",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/targets/{id}",
        "/targets/{id}",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/scan-configs",
        "/scan-configs",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/scan-configs/{id}",
        "/scan-configs/{id}",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/scanners",
        "/scanners",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/scanners/{id}",
        "/scanners/{id}",
    );
    normalized_paths.insert(
        "/openapi.json".to_string(),
        json!({
            "get": {
                "operationId": "getOpenApiDocument",
                "tags": ["System"],
                "summary": "Get generated OpenAPI document",
                "description": "Returns the generated OpenAPI document for the implemented REST surface.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Generated OpenAPI document",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                }
                            }
                        }
                    }
                }
            }
        }),
    );
    document["paths"] = Value::Object(normalized_paths);

    for (path, method) in [
        ("/health", "get"),
        ("/ready", "get"),
        ("/version", "get"),
        ("/openapi.json", "get"),
    ] {
        if let Some(operation) = document["paths"][path][method].as_object_mut() {
            operation.insert("security".to_string(), json!([]));
        }
    }

    // Session endpoints: POST uses basicAuth, GET/DELETE use bearerAuth (inherited).
    if let Some(operation) = document["paths"]["/sessions"]["post"].as_object_mut() {
        operation.insert("security".to_string(), json!([{"basicAuth": []}]));
    }
    // GET and DELETE on /sessions/{token} use global bearer security (no override needed)
    for (path, method) in [
        ("/sessions/{token}", "get"),
        ("/sessions/{token}", "delete"),
    ] {
        if let Some(operation) = document["paths"][path][method].as_object_mut() {
            operation.remove("security");
        }
    }

    // Resource endpoints use global bearer security (remove per-handler overrides).
    for (path, method) in [
        ("/targets", "get"),
        ("/targets", "post"),
        ("/targets/{id}", "get"),
        ("/targets/{id}", "put"),
        ("/targets/{id}", "delete"),
        ("/scan-configs", "get"),
        ("/scan-configs", "post"),
        ("/scan-configs/{id}", "get"),
        ("/scan-configs/{id}", "put"),
        ("/scan-configs/{id}", "delete"),
        ("/scanners", "get"),
        ("/scanners/{id}", "get"),
    ] {
        if let Some(operation) = document["paths"][path][method].as_object_mut() {
            operation.remove("security");
        }
    }

    tighten_list_query_parameters(&mut document, "/targets");
    tighten_list_query_parameters(&mut document, "/scan-configs");
    tighten_list_query_parameters(&mut document, "/scanners");
    tighten_target_payload_schemas(&mut document);
    tighten_scan_config_payload_schemas(&mut document);
    ensure_problem_detail_schema(&mut document);
    ensure_basic_auth_scheme(&mut document);
    strip_nullable_types(&mut document);
    document
}

fn tighten_list_query_parameters(document: &mut Value, path: &str) {
    if let Some(parameters) = document["paths"][path]["get"]["parameters"].as_array_mut() {
        for parameter in parameters {
            match parameter["name"].as_str() {
                Some("page") => {
                    parameter["schema"]["minimum"] = json!(1);
                    parameter["schema"]["default"] = json!(1);
                }
                Some("perPage") => {
                    parameter["schema"]["minimum"] = json!(1);
                    parameter["schema"]["maximum"] = json!(1000);
                    parameter["schema"]["default"] = json!(25);
                }
                _ => {}
            }
        }
    }
}

fn tighten_target_payload_schemas(document: &mut Value) {
    document["components"]["schemas"]["CreateTarget"]["properties"]["hosts"]["minItems"] = json!(1);
}

fn tighten_scan_config_payload_schemas(document: &mut Value) {
    // CreateScanConfig requires name — ensure the schema reflects this.
    if let Some(required) = document["components"]["schemas"]["CreateScanConfig"]["required"]
        .as_array_mut()
    {
        if !required.iter().any(|v| v.as_str() == Some("name")) {
            required.push(json!("name"));
        }
    }
}

fn ensure_problem_detail_schema(document: &mut Value) {
    let schemas = document["components"]["schemas"]
        .as_object_mut()
        .expect("generated OpenAPI document must contain components.schemas");

    schemas.insert(
        "ProblemDetail".to_string(),
        json!({
            "type": "object",
            "required": ["type", "title", "status"],
            "properties": {
                "type": {
                    "type": "string",
                    "format": "uri"
                },
                "title": {
                    "type": "string"
                },
                "status": {
                    "type": "integer"
                },
                "detail": {
                    "type": "string"
                },
                "instance": {
                    "type": "string",
                    "format": "uri-reference"
                }
            }
        }),
    );
}

fn ensure_basic_auth_scheme(document: &mut Value) {
    if let Some(security_schemes) = document["components"]["securitySchemes"].as_object_mut() {
        security_schemes.insert(
            "basicAuth".to_string(),
            json!({
                "type": "http",
                "scheme": "basic",
                "description": "HTTP Basic credentials used to create a session."
            }),
        );
    }
}

fn strip_nullable_types(value: &mut Value) {
    *value = normalize_nullable_schema(std::mem::take(value));
}

fn normalize_nullable_schema(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut object = object
                .into_iter()
                .map(|(key, value)| (key, normalize_nullable_schema(value)))
                .collect::<Map<String, Value>>();

            if let Some(Value::Array(types)) = object.get_mut("type") {
                let mut filtered = types
                    .iter()
                    .filter(|ty| ty.as_str() != Some("null"))
                    .cloned()
                    .collect::<Vec<_>>();
                if filtered.len() == 1 {
                    object.insert("type".to_string(), filtered.remove(0));
                } else if filtered.len() != types.len() {
                    *types = filtered;
                }
            }

            collapse_nullable_combinator(&object, "anyOf")
                .or_else(|| collapse_nullable_combinator(&object, "oneOf"))
                .unwrap_or(Value::Object(object))
        }
        Value::Array(array) => Value::Array(
            array
                .into_iter()
                .map(normalize_nullable_schema)
                .collect::<Vec<_>>(),
        ),
        other => other,
    }
}

fn collapse_nullable_combinator(object: &Map<String, Value>, key: &str) -> Option<Value> {
    let Value::Array(options) = object.get(key)? else {
        return None;
    };

    let filtered = options
        .iter()
        .filter(|option| !is_null_schema(option))
        .cloned()
        .collect::<Vec<_>>();

    if filtered.len() == options.len() {
        return None;
    }

    if filtered.len() == 1 {
        let mut remaining = filtered.into_iter().next().unwrap();
        if let Value::Object(ref mut remaining_object) = remaining {
            for (other_key, other_value) in object {
                if other_key != key && !remaining_object.contains_key(other_key) {
                    remaining_object.insert(other_key.clone(), other_value.clone());
                }
            }
        }
        Some(remaining)
    } else {
        let mut normalized = object.clone();
        normalized.insert(key.to_string(), Value::Array(filtered));
        Some(Value::Object(normalized))
    }
}

fn is_null_schema(value: &Value) -> bool {
    matches!(value, Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("null"))
}

fn copy_path(
    source_paths: &Map<String, Value>,
    normalized_paths: &mut Map<String, Value>,
    source: &str,
    target: &str,
) {
    if let Some(path_item) = source_paths.get(source) {
        normalized_paths.insert(target.to_string(), path_item.clone());
    }
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
            name: "Sessions".to_string(),
            description: Some("Session lifecycle".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "Targets".to_string(),
            description: Some("Scan target management".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "Scan Configs".to_string(),
            description: Some("Scan configuration management".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "Scanners".to_string(),
            description: Some("Scanner management".to_string()),
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

// ============================================================================
// OpenAPI endpoint documentation transforms
// ============================================================================

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
    op.id("getReadiness")
        .tag("System")
        .summary("Readiness probe")
        .description("Indicates whether the service is ready to handle requests.")
        .response_with::<200, Json<ReadinessStatusDoc>, _>(ok_json("Service is ready"))
        .response_with::<503, Json<ReadinessStatusDoc>, _>(ok_json("Service is not ready"))
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

// -- Session endpoints -------------------------------------------------------

/// OpenAPI transform for `POST /api/v1/sessions`.
pub(crate) fn create_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createSession")
        .tag("Sessions")
        .summary("Create a new session")
        .description(
            "Authenticates with the supplied Basic credentials and returns an opaque \
             session token. Include the token as a Bearer token on all subsequent requests.",
        )
        .security_requirement("basicAuth")
        .response_with::<201, Json<SessionCreatedDoc>, _>(ok_json("Session created"));

    let op = problem_response::<401>(op, "Authentication failed");
    problem_response::<502>(op, "Backend service unreachable or connection failed")
}

/// OpenAPI transform for `GET /api/v1/sessions/{token}`.
pub(crate) fn get_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getSession")
        .tag("Sessions")
        .summary("Inspect a session")
        .description("Returns the current state and metadata for a session.")
        .security_requirement("bearerAuth")
        .input::<Path<SessionTokenPathDoc>>()
        .response_with::<200, Json<SessionInfoDoc>, _>(ok_json("Session details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Session not found")
}

/// OpenAPI transform for `DELETE /api/v1/sessions/{token}`.
pub(crate) fn delete_session_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteSession")
        .tag("Sessions")
        .summary("Close and destroy a session")
        .description("Ends the session and invalidates the token immediately.")
        .security_requirement("bearerAuth")
        .input::<Path<SessionTokenPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Session closed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Session not found")
}

// -- Target endpoints --------------------------------------------------------

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

// -- Scan Config endpoints ---------------------------------------------------

/// OpenAPI transform for `GET /api/v1/scan-configs`.
pub(crate) fn list_scan_configs_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfigs")
        .tag("Scan Configs")
        .summary("List scan configurations")
        .description("Returns a paginated list of scan configurations.")
        .security_requirement("bearerAuth")
        .input::<Query<ListQueryDoc>>()
        .response_with::<200, Json<ScanConfigListDoc>, _>(ok_json(
            "Paginated list of scan configs",
        ));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/scan-configs`.
pub(crate) fn create_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createScanConfig")
        .tag("Scan Configs")
        .summary("Create a scan configuration")
        .description("Creates a new scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateScanConfigDoc>>()
        .response_with::<201, Json<ResourceCreatedDoc>, _>(ok_json("Scan config created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/scan-configs/{id}`.
pub(crate) fn get_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanConfig")
        .tag("Scan Configs")
        .summary("Get a scan configuration")
        .description("Returns the details for a single scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScanConfigDoc>, _>(ok_json("Scan config details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/scan-configs/{id}`.
pub(crate) fn update_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyScanConfig")
        .tag("Scan Configs")
        .summary("Modify a scan configuration")
        .description("Updates an existing scan configuration.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyScanConfigDoc>)>()
        .response_with::<200, Json<ScanConfigDoc>, _>(ok_json("Scan config updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/scan-configs/{id}`.
pub(crate) fn delete_scan_config_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteScanConfig")
        .tag("Scan Configs")
        .summary("Delete a scan configuration")
        .description("Deletes an existing scan configuration.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Scan config deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

// -- Scanner endpoints -------------------------------------------------------

/// OpenAPI transform for `GET /api/v1/scanners`.
pub(crate) fn list_scanners_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanners")
        .tag("Scanners")
        .summary("List scanners")
        .description("Returns a paginated list of scanners.")
        .security_requirement("bearerAuth")
        .input::<Query<ListQueryDoc>>()
        .response_with::<200, Json<ScannerListDoc>, _>(ok_json("Paginated list of scanners"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/scanners/{id}`.
pub(crate) fn get_scanner_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getScanner")
        .tag("Scanners")
        .summary("Get a scanner")
        .description("Returns the details for a single scanner.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ScannerDoc>, _>(ok_json("Scanner details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

// ============================================================================
// OpenAPI document-only schema types
// ============================================================================

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

// -- Session schemas ---------------------------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "SessionCreated")]
struct SessionCreatedDoc {
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: u64,
    #[serde(rename = "gmpVersion")]
    gmp_version: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "SessionInfo")]
struct SessionInfoDoc {
    #[serde(rename = "sessionToken")]
    session_token: String,
    user: String,
    state: SessionStateDoc,
    #[serde(rename = "createdAt")]
    #[schemars(schema_with = "datetime_schema")]
    created_at: String,
    #[serde(rename = "lastUsedAt")]
    #[schemars(schema_with = "datetime_schema")]
    last_used_at: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum SessionStateDoc {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "closed")]
    Closed,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct SessionTokenPathDoc {
    token: String,
}

// -- Target schemas ----------------------------------------------------------

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

// -- Scan Config schemas -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ScanConfig")]
struct ScanConfigDoc {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "familyCount", skip_serializing_if = "Option::is_none")]
    family_count: Option<u32>,
    #[serde(rename = "nvtCount", skip_serializing_if = "Option::is_none")]
    nvt_count: Option<u32>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    config_type: Option<i32>,
    #[serde(rename = "inUse")]
    in_use: bool,
    writable: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ScanConfigList")]
struct ScanConfigListDoc {
    data: Vec<ScanConfigDoc>,
    pagination: PaginationDoc,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateScanConfig")]
struct CreateScanConfigDoc {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "baseScanConfigId", skip_serializing_if = "Option::is_none")]
    base_scan_config_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyScanConfig")]
struct ModifyScanConfigDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

// -- Scanner schemas ---------------------------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "Scanner")]
struct ScannerDoc {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i32>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    scanner_type: Option<ScannerTypeDoc>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ScannerList")]
struct ScannerListDoc {
    data: Vec<ScannerDoc>,
    pagination: PaginationDoc,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum ScannerTypeDoc {
    OpenVAS,
    CVE,
    OSP,
}

// -- Shared query/path schemas -----------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct TargetListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ListQueryDoc {
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
        AuthPort, CreateScanConfigInput, CreateTargetInput, GatewayError, ModifyScanConfigInput,
        ModifyTargetInput, ReadinessStatus, ScanConfig, ScanConfigPage, ScanConfigPort,
        ScanConfigQuery, Scanner, ScannerPage, ScannerPort, ScannerQuery, SystemPort, Target,
        TargetPage, TargetPort, TargetQuery,
    };

    struct StubSystem;
    struct StubTarget;
    struct StubAuth;
    struct StubScanConfig;
    struct StubScanner;

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

    #[async_trait]
    impl AuthPort for StubAuth {
        async fn authenticate_session(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn disconnect_session(&self, _: &str) -> Result<(), GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }
    }

    #[async_trait]
    impl ScanConfigPort for StubScanConfig {
        async fn list_scan_configs(
            &self,
            _: &str,
            _: &ScanConfigQuery,
        ) -> Result<ScanConfigPage, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn create_scan_config(
            &self,
            _: &str,
            _: CreateScanConfigInput,
        ) -> Result<String, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn get_scan_config(&self, _: &str, _: &str) -> Result<ScanConfig, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn modify_scan_config(
            &self,
            _: &str,
            _: &str,
            _: ModifyScanConfigInput,
        ) -> Result<ScanConfig, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn delete_scan_config(&self, _: &str, _: &str) -> Result<(), GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }
    }

    #[async_trait]
    impl ScannerPort for StubScanner {
        async fn list_scanners(
            &self,
            _: &str,
            _: &ScannerQuery,
        ) -> Result<ScannerPage, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }

        async fn get_scanner(&self, _: &str, _: &str) -> Result<Scanner, GatewayError> {
            unreachable!("OpenAPI generation does not execute handlers")
        }
    }

    /// The generated OpenAPI document must include the curated operationIds and
    /// response status codes for every implemented endpoint so that the served
    /// contract stays aligned with the repository specification.
    #[test]
    fn generated_openapi_subset_matches_curated_spec() {
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();
        let system_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/system.yaml")).unwrap();
        let targets_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();
        let sessions_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/sessions.yaml")).unwrap();
        let scan_configs_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/scan-configs.yaml")).unwrap();
        let scanners_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/scanners.yaml")).unwrap();

        let checks = [
            ("/health", "get", &system_spec, "/health", &["200"] as &[_]),
            ("/ready", "get", &system_spec, "/ready", &["200", "503"]),
            ("/version", "get", &system_spec, "/version", &["200", "502"]),
            (
                "/openapi.json",
                "get",
                &system_spec,
                "/openapi.json",
                &["200"],
            ),
            // Sessions
            (
                "/sessions",
                "post",
                &sessions_spec,
                "/sessions",
                &["201", "401", "502"],
            ),
            (
                "/sessions/{token}",
                "get",
                &sessions_spec,
                "/sessions/{token}",
                &["200", "404"],
            ),
            (
                "/sessions/{token}",
                "delete",
                &sessions_spec,
                "/sessions/{token}",
                &["204", "404"],
            ),
            // Targets
            (
                "/targets",
                "get",
                &targets_spec,
                "/targets",
                &["200", "401"],
            ),
            (
                "/targets",
                "post",
                &targets_spec,
                "/targets",
                &["201", "400", "401"],
            ),
            (
                "/targets/{id}",
                "get",
                &targets_spec,
                "/targets/{id}",
                &["200", "401", "404"],
            ),
            (
                "/targets/{id}",
                "put",
                &targets_spec,
                "/targets/{id}",
                &["200", "400", "401", "404"],
            ),
            (
                "/targets/{id}",
                "delete",
                &targets_spec,
                "/targets/{id}",
                &["204", "401", "404"],
            ),
            // Scan Configs
            (
                "/scan-configs",
                "get",
                &scan_configs_spec,
                "/scan-configs",
                &["200", "401"],
            ),
            (
                "/scan-configs",
                "post",
                &scan_configs_spec,
                "/scan-configs",
                &["201", "400", "401"],
            ),
            (
                "/scan-configs/{id}",
                "get",
                &scan_configs_spec,
                "/scan-configs/{id}",
                &["200", "401", "404"],
            ),
            (
                "/scan-configs/{id}",
                "put",
                &scan_configs_spec,
                "/scan-configs/{id}",
                &["200", "400", "401", "404"],
            ),
            (
                "/scan-configs/{id}",
                "delete",
                &scan_configs_spec,
                "/scan-configs/{id}",
                &["204", "401", "404"],
            ),
            // Scanners
            (
                "/scanners",
                "get",
                &scanners_spec,
                "/scanners",
                &["200", "401"],
            ),
            (
                "/scanners/{id}",
                "get",
                &scanners_spec,
                "/scanners/{id}",
                &["200", "401", "404"],
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
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();

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

    /// Session schemas are present in the generated document.
    #[test]
    fn generated_openapi_includes_session_schemas() {
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();
        let schemas = generated["components"]["schemas"].as_object().unwrap();

        assert!(
            schemas.contains_key("SessionCreated"),
            "missing SessionCreated schema"
        );
        assert!(
            schemas.contains_key("SessionInfo"),
            "missing SessionInfo schema"
        );
    }

    /// Scan config and scanner schemas are present in the generated document.
    #[test]
    fn generated_openapi_includes_scan_config_and_scanner_schemas() {
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();
        let schemas = generated["components"]["schemas"].as_object().unwrap();

        assert!(
            schemas.contains_key("ScanConfig"),
            "missing ScanConfig schema"
        );
        assert!(
            schemas.contains_key("ScanConfigList"),
            "missing ScanConfigList schema"
        );
        assert!(
            schemas.contains_key("CreateScanConfig"),
            "missing CreateScanConfig schema"
        );
        assert!(
            schemas.contains_key("Scanner"),
            "missing Scanner schema"
        );
        assert!(
            schemas.contains_key("ScannerList"),
            "missing ScannerList schema"
        );
    }

    /// ScanConfig schema has the required fields from the curated spec.
    #[test]
    fn generated_scan_config_schema_has_required_fields() {
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();
        let scan_config_required = generated["components"]["schemas"]["ScanConfig"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert!(scan_config_required.contains("id"));
        assert!(scan_config_required.contains("name"));
    }

    /// Scanner schema has the required fields from the curated spec.
    #[test]
    fn generated_scanner_schema_has_required_fields() {
        let generated =
            build_openapi::<StubSystem, StubTarget, StubAuth, StubScanConfig, StubScanner>();
        let scanner_required = generated["components"]["schemas"]["Scanner"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert!(scanner_required.contains("id"));
        assert!(scanner_required.contains("name"));
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
