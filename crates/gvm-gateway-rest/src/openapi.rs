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

// Runtime DTO imports — these types own both the JSON wire format and the
// OpenAPI schema.
use crate::{
    dto::ResourceCreatedResponse,
    reports::{ReportListResponse, ReportResponse},
    results::{ResultListResponse, ResultResponse},
    router::{HealthStatusResponse, ReadinessStatusResponse, VersionInfoResponse},
    scan_configs::{ScanConfigListResponse, ScanConfigResponse},
    scanners::{ScannerListResponse, ScannerResponse},
    sessions::{SessionCreatedResponse, SessionInfoResponse},
    targets::{TargetListResponse, TargetResponse},
    tasks::{TaskActionResponse, TaskListResponse, TaskResponse},
};

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
            "name": "Tasks",
            "description": "Scan task management"
        },
        {
            "name": "Reports",
            "description": "Scan report management"
        },
        {
            "name": "Results",
            "description": "Scan result management"
        },
        {
            "name": "Scan Configs",
            "description": "Scan configuration management"
        },
        {
            "name": "Scanners",
            "description": "Scanner information"
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
        "/api/v1/tasks",
        "/tasks",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/tasks/{id}",
        "/tasks/{id}",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/tasks/{id}/start",
        "/tasks/{id}/start",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/tasks/{id}/stop",
        "/tasks/{id}/stop",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/tasks/{id}/resume",
        "/tasks/{id}/resume",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/reports",
        "/reports",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/reports/{id}",
        "/reports/{id}",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/reports/{id}/results",
        "/reports/{id}/results",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/results",
        "/results",
    );
    copy_path(
        &source_paths,
        &mut normalized_paths,
        "/api/v1/results/{id}",
        "/results/{id}",
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

    for (path, method) in [
        ("/targets", "get"),
        ("/targets", "post"),
        ("/targets/{id}", "get"),
        ("/targets/{id}", "put"),
        ("/targets/{id}", "delete"),
        ("/reports", "get"),
        ("/reports/{id}", "get"),
        ("/reports/{id}", "delete"),
        ("/reports/{id}/results", "get"),
        ("/results", "get"),
        ("/results/{id}", "get"),
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

    tighten_target_query_parameters(&mut document);
    tighten_target_payload_schemas(&mut document);
    tighten_task_query_parameters(&mut document);
    tighten_task_payload_schemas(&mut document);
    tighten_list_query_parameters(&mut document, "/reports");
    tighten_list_query_parameters(&mut document, "/results");
    tighten_list_query_parameters(&mut document, "/reports/{id}/results");
    tighten_list_query_parameters(&mut document, "/scan-configs");
    tighten_list_query_parameters(&mut document, "/scanners");
    tighten_report_get_parameters(&mut document);
    ensure_problem_detail_schema(&mut document);
    ensure_basic_auth_scheme(&mut document);
    strip_nullable_types(&mut document);
    document
}

fn tighten_target_query_parameters(document: &mut Value) {
    if let Some(parameters) = document["paths"]["/targets"]["get"]["parameters"].as_array_mut() {
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

fn tighten_report_get_parameters(document: &mut Value) {
    if let Some(parameters) = document["paths"]["/reports/{id}"]["get"]["parameters"].as_array_mut()
    {
        for parameter in parameters {
            if parameter["name"].as_str() == Some("ignorePagination") {
                parameter["schema"]["default"] = json!(false);
            }
        }
    }
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
                Some("filterId") => {
                    parameter["schema"]["format"] = json!("uuid");
                }
                _ => {}
            }
        }
    }
}

fn tighten_target_payload_schemas(document: &mut Value) {
    document["components"]["schemas"]["CreateTarget"]["properties"]["hosts"]["minItems"] = json!(1);
}

fn tighten_task_query_parameters(document: &mut Value) {
    if let Some(parameters) = document["paths"]["/tasks"]["get"]["parameters"].as_array_mut() {
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

fn tighten_task_payload_schemas(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    if let Some(create_task) = schemas.get_mut("CreateTask") {
        if let Some(props) = create_task.get_mut("properties") {
            if let Some(target_id) = props.get_mut("targetId") {
                target_id["format"] = json!("uuid");
            }
            if let Some(scan_config_id) = props.get_mut("scanConfigId") {
                scan_config_id["format"] = json!("uuid");
            }
            if let Some(scanner_id) = props.get_mut("scannerId") {
                scanner_id["format"] = json!("uuid");
            }
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
            name: "Reports".to_string(),
            description: Some("Scan report management".to_string()),
            external_docs: None,
            extensions: Default::default(),
        })
        .tag(Tag {
            name: "Results".to_string(),
            description: Some("Scan result management".to_string()),
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
            description: Some("Scanner information".to_string()),
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
        .response_with::<200, Json<HealthStatusResponse>, _>(ok_json("Service is alive"))
}

/// OpenAPI transform for `GET /ready`.
pub(crate) fn ready_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.id("getReadiness")
        .tag("System")
        .summary("Readiness probe")
        .description("Indicates whether the service is ready to handle requests.")
        .response_with::<200, Json<ReadinessStatusResponse>, _>(ok_json("Service is ready"))
        .response_with::<503, Json<ReadinessStatusResponse>, _>(ok_json("Service is not ready"))
}

/// OpenAPI transform for `GET /api/v1/version`.
pub(crate) fn version_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getVersion")
        .tag("System")
        .summary("Get API and GMP version information")
        .description("Returns the gateway API version together with the connected GMP version.")
        .response_with::<200, Json<VersionInfoResponse>, _>(ok_json("Version information"));

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
        .response_with::<201, Json<SessionCreatedResponse>, _>(ok_json("Session created"));

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
        .response_with::<200, Json<SessionInfoResponse>, _>(ok_json("Session details"));

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
        .response_with::<200, Json<TargetListResponse>, _>(ok_json("Paginated list of targets"));

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
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Target created"));

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
        .response_with::<200, Json<TargetResponse>, _>(ok_json("Target details"));

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
        .response_with::<200, Json<TargetResponse>, _>(ok_json("Target updated"));

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

// -- Task endpoints ----------------------------------------------------------

/// OpenAPI transform for `GET /api/v1/tasks`.
pub(crate) fn list_tasks_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTasks")
        .tag("Tasks")
        .summary("List tasks")
        .description("Returns a paginated list of tasks.")
        .security_requirement("bearerAuth")
        .input::<Query<TaskListQueryDoc>>()
        .response_with::<200, Json<TaskListResponse>, _>(ok_json("Paginated list of tasks"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `POST /api/v1/tasks`.
pub(crate) fn create_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("createTask")
        .tag("Tasks")
        .summary("Create a task")
        .description("Creates a new scan task.")
        .security_requirement("bearerAuth")
        .input::<Json<CreateTaskDoc>>()
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Task created"));

    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/tasks/{id}`.
pub(crate) fn get_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getTask")
        .tag("Tasks")
        .summary("Get a task")
        .description("Returns the details for a single task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `PUT /api/v1/tasks/{id}`.
pub(crate) fn update_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("modifyTask")
        .tag("Tasks")
        .summary("Modify a task")
        .description("Updates an existing task.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Json<ModifyTaskDoc>)>()
        .response_with::<200, Json<TaskResponse>, _>(ok_json("Task updated"));

    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/tasks/{id}`.
pub(crate) fn delete_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteTask")
        .tag("Tasks")
        .summary("Delete a task")
        .description("Deletes an existing task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Task deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/start`.
pub(crate) fn start_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("startTask")
        .tag("Tasks")
        .summary("Start a task")
        .description("Starts a scan task. Returns the report identifier created by the action.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task started"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    let op = problem_response::<409>(op, "Resource state conflict");
    problem_response::<504>(op, "Backend service did not respond in time")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/stop`.
pub(crate) fn stop_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("stopTask")
        .tag("Tasks")
        .summary("Stop a running task")
        .description("Stops a currently running scan task.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, (), _>(|response| response.description("Task stopped"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

/// OpenAPI transform for `POST /api/v1/tasks/{id}/resume`.
pub(crate) fn resume_task_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("resumeTask")
        .tag("Tasks")
        .summary("Resume a stopped task")
        .description("Resumes a stopped scan task. Returns the report identifier.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<TaskActionResponse>, _>(ok_json("Task resumed"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<404>(op, "Resource not found");
    problem_response::<409>(op, "Resource state conflict")
}

// -- Report endpoints --------------------------------------------------------

/// OpenAPI transform for `GET /api/v1/reports`.
pub(crate) fn list_reports_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReports")
        .tag("Reports")
        .summary("List reports")
        .description("Returns a paginated list of reports.")
        .security_requirement("bearerAuth")
        .input::<Query<ReportListQueryDoc>>()
        .response_with::<200, Json<ReportListResponse>, _>(ok_json("Paginated list of reports"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}`.
pub(crate) fn get_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReport")
        .tag("Reports")
        .summary("Get a report")
        .description("Returns the details for a single report with embedded results.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<GetReportQueryDoc>)>()
        .response_with::<200, Json<ReportResponse>, _>(ok_json(
            "Report details with embedded results",
        ));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `DELETE /api/v1/reports/{id}`.
pub(crate) fn delete_report_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("deleteReport")
        .tag("Reports")
        .summary("Delete a report")
        .description("Deletes an existing report.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<204, (), _>(|response| response.description("Report deleted"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

/// OpenAPI transform for `GET /api/v1/reports/{id}/results`.
pub(crate) fn get_report_results_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getReportResults")
        .tag("Reports")
        .summary("Get paginated results for a report")
        .description("Returns a paginated list of results for a specific report.")
        .security_requirement("bearerAuth")
        .input::<(Path<ResourceIdPathDoc>, Query<ReportResultsQueryDoc>)>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json("Paginated list of results"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

// -- Result endpoints --------------------------------------------------------

/// OpenAPI transform for `GET /api/v1/results`.
pub(crate) fn list_results_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getResults")
        .tag("Results")
        .summary("List results")
        .description("Returns a paginated list of results.")
        .security_requirement("bearerAuth")
        .input::<Query<ResultListQueryDoc>>()
        .response_with::<200, Json<ResultListResponse>, _>(ok_json("Paginated list of results"));

    problem_response::<401>(op, "Authentication required or session expired")
}

/// OpenAPI transform for `GET /api/v1/results/{id}`.
pub(crate) fn get_result_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = op
        .id("getResult")
        .tag("Results")
        .summary("Get a result")
        .description("Returns the details for a single result.")
        .security_requirement("bearerAuth")
        .input::<Path<ResourceIdPathDoc>>()
        .response_with::<200, Json<ResultResponse>, _>(ok_json("Result details"));

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
        .input::<Query<ScanConfigListQueryDoc>>()
        .response_with::<200, Json<ScanConfigListResponse>, _>(ok_json(
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
        .response_with::<201, Json<ResourceCreatedResponse>, _>(ok_json("Scan config created"));

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
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config details"));

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
        .response_with::<200, Json<ScanConfigResponse>, _>(ok_json("Scan config updated"));

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
        .input::<Query<ScannerListQueryDoc>>()
        .response_with::<200, Json<ScannerListResponse>, _>(ok_json("Paginated list of scanners"));

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
        .response_with::<200, Json<ScannerResponse>, _>(ok_json("Scanner details"));

    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

// ============================================================================
// OpenAPI document-only schema types
//
// These types exist solely for OpenAPI schema generation.  They are NOT used
// at runtime for serialisation — see the handler modules for runtime DTOs.
// They are kept because their field shapes intentionally differ from the
// runtime request/query types (e.g. required vs optional fields, Uuid vs
// String for IDs).
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

// -- Session path parameter --------------------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct SessionTokenPathDoc {
    token: String,
}

// -- Shared path/query parameter schemas -------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
struct ResourceIdPathDoc {
    id: Uuid,
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

// -- Target request body schemas ---------------------------------------------

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

// -- Task request body / query schemas ---------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct TaskListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTask")]
struct CreateTaskDoc {
    name: String,
    comment: Option<String>,
    #[serde(rename = "targetId")]
    target_id: Uuid,
    #[serde(rename = "scanConfigId")]
    scan_config_id: Uuid,
    #[serde(rename = "scannerId")]
    scanner_id: Uuid,
    #[serde(rename = "scheduleId")]
    schedule_id: Option<Uuid>,
    #[serde(rename = "alertIds")]
    alert_ids: Option<Vec<Uuid>>,
    alterable: Option<bool>,
    #[serde(rename = "hostsOrdering")]
    hosts_ordering: Option<HostsOrderingDoc>,
    observers: Option<Vec<String>>,
    #[serde(rename = "schedulePeriods")]
    schedule_periods: Option<u32>,
    preferences: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyTask")]
struct ModifyTaskDoc {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "targetId")]
    target_id: Option<Uuid>,
    #[serde(rename = "scanConfigId")]
    scan_config_id: Option<Uuid>,
    #[serde(rename = "scannerId")]
    scanner_id: Option<Uuid>,
    #[serde(rename = "scheduleId")]
    schedule_id: Option<Uuid>,
    #[serde(rename = "alertIds")]
    alert_ids: Option<Vec<Uuid>>,
    #[serde(rename = "hostsOrdering")]
    hosts_ordering: Option<HostsOrderingDoc>,
    observers: Option<Vec<String>>,
    #[serde(rename = "schedulePeriods")]
    schedule_periods: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum HostsOrderingDoc {
    #[serde(rename = "sequential")]
    Sequential,
    #[serde(rename = "random")]
    Random,
    #[serde(rename = "reverse")]
    Reverse,
}

// -- Report / result query schemas -------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ReportListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct GetReportQueryDoc {
    #[serde(rename = "ignorePagination")]
    ignore_pagination: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ReportResultsQueryDoc {
    filter: Option<String>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ResultListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

// -- Scan config request body / query schemas --------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ScanConfigListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateScanConfig")]
struct CreateScanConfigDoc {
    name: String,
    comment: Option<String>,
    #[serde(rename = "baseScanConfigId")]
    base_scan_config_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyScanConfig")]
struct ModifyScanConfigDoc {
    name: Option<String>,
    comment: Option<String>,
}

// -- Scanner query schemas ---------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct ScannerListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use crate::router::build_openapi;

    #[test]
    fn generated_openapi_subset_matches_curated_spec() {
        let generated = build_openapi();
        let system_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/system.yaml")).unwrap();
        let targets_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();
        let sessions_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/sessions.yaml")).unwrap();
        let tasks_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/tasks.yaml")).unwrap();
        let reports_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/reports.yaml")).unwrap();
        let results_spec: Value =
            serde_yaml::from_str(include_str!("../../../spec/rest-api/results.yaml")).unwrap();
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
            ("/tasks", "get", &tasks_spec, "/tasks", &["200", "401"]),
            (
                "/tasks",
                "post",
                &tasks_spec,
                "/tasks",
                &["201", "400", "401"],
            ),
            (
                "/tasks/{id}",
                "get",
                &tasks_spec,
                "/tasks/{id}",
                &["200", "401", "404"],
            ),
            (
                "/tasks/{id}",
                "put",
                &tasks_spec,
                "/tasks/{id}",
                &["200", "400", "401", "404"],
            ),
            (
                "/tasks/{id}",
                "delete",
                &tasks_spec,
                "/tasks/{id}",
                &["204", "401", "404"],
            ),
            (
                "/tasks/{id}/start",
                "post",
                &tasks_spec,
                "/tasks/{id}/start",
                &["200", "401", "404", "409", "504"],
            ),
            (
                "/tasks/{id}/stop",
                "post",
                &tasks_spec,
                "/tasks/{id}/stop",
                &["200", "401", "404", "409"],
            ),
            (
                "/tasks/{id}/resume",
                "post",
                &tasks_spec,
                "/tasks/{id}/resume",
                &["200", "401", "404", "409"],
            ),
            (
                "/reports",
                "get",
                &reports_spec,
                "/reports",
                &["200", "401"],
            ),
            (
                "/reports/{id}",
                "get",
                &reports_spec,
                "/reports/{id}",
                &["200", "401", "404"],
            ),
            (
                "/reports/{id}",
                "delete",
                &reports_spec,
                "/reports/{id}",
                &["204", "401", "404"],
            ),
            (
                "/reports/{id}/results",
                "get",
                &reports_spec,
                "/reports/{id}/results",
                &["200", "401", "404"],
            ),
            (
                "/results",
                "get",
                &results_spec,
                "/results",
                &["200", "401"],
            ),
            (
                "/results/{id}",
                "get",
                &results_spec,
                "/results/{id}",
                &["200", "401", "404"],
            ),
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
        let generated = build_openapi();

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

    #[test]
    fn generated_openapi_includes_session_schemas() {
        let generated = build_openapi();
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

    #[test]
    fn generated_openapi_includes_task_schemas() {
        let generated = build_openapi();
        let schemas = generated["components"]["schemas"].as_object().unwrap();

        assert!(schemas.contains_key("Task"), "missing Task schema");
        assert!(schemas.contains_key("TaskList"), "missing TaskList schema");
        assert!(
            schemas.contains_key("CreateTask"),
            "missing CreateTask schema"
        );
        assert!(
            schemas.contains_key("ModifyTask"),
            "missing ModifyTask schema"
        );
        assert!(
            schemas.contains_key("TaskAction"),
            "missing TaskAction schema"
        );
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
