// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! OpenAPI generation helpers for the REST adapter.

use aide::{
    openapi::{License, SecurityScheme, Server},
    transform::{TransformOpenApi, TransformOperation, TransformResponse},
};
use axum::http::Method;
use axum::Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

// Runtime DTO imports are no longer needed centrally — OpenAPI transforms
// now live alongside their handlers in each module.
use crate::{
    auth_policy::{classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy},
    open_enum::document_open_enum_schema,
};

pub(crate) fn ok_json<T>(
    description: &'static str,
) -> impl FnOnce(TransformResponse<T>) -> TransformResponse<T> {
    move |response| response.description(description)
}

pub(crate) fn problem_response<'a, const N: u16>(
    op: TransformOperation<'a>,
    description: &'static str,
) -> TransformOperation<'a> {
    op.response_with::<N, Json<ProblemDetailDoc>, _>(|response| {
        response
            .description(description)
            .example(ProblemDetailDoc::example())
    })
}

/// Finalize the generated OpenAPI document so its served contract shape matches
/// the curated repository spec for the implemented REST surface.
pub(crate) fn finalize_document(mut document: Value) -> Value {
    document["servers"] = json!([
        {
            "url": "/api/v1",
            "description": "Base path for versioned API endpoints"
        }
    ]);
    document["security"] = json!([
        {
            "bearerAuth": []
        },
        {
            "basicAuth": []
        }
    ]);
    document["tags"] = openapi_tags();

    let source_paths = document["paths"].as_object().cloned().unwrap_or_default();
    let mut normalized_paths = normalize_paths(&source_paths);
    add_probe_server_overrides(&mut normalized_paths);
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

    for path in [
        "/session",
        "/targets",
        "/alerts",
        "/schedules",
        "/credentials",
        "/port-lists",
        "/tasks",
        "/scan-configs",
        "/notes",
        "/overrides",
    ] {
        add_location_header_to_created_response(&mut normalized_paths, path);
    }
    add_retry_after_header_to_too_many_requests_response(&mut normalized_paths, "/session");

    synchronize_report_export_responses(&mut normalized_paths);
    document_backend_unavailable_responses(&mut normalized_paths);

    document["paths"] = Value::Object(normalized_paths);

    apply_route_auth_security(&mut document);

    tighten_target_query_parameters(&mut document);
    tighten_target_payload_schemas(&mut document);
    tighten_list_query_parameters(&mut document, "/alerts");
    tighten_list_query_parameters(&mut document, "/schedules");
    tighten_list_query_parameters(&mut document, "/credentials");
    tighten_list_query_parameters(&mut document, "/port-lists");
    tighten_alert_payload_schemas(&mut document);
    tighten_schedule_payload_schemas(&mut document);
    tighten_credential_payload_schemas(&mut document);
    tighten_port_list_payload_schemas(&mut document);
    tighten_alert_enums(&mut document);
    tighten_credential_enums(&mut document);
    tighten_feed_schema(&mut document);
    tighten_task_query_parameters(&mut document);
    tighten_task_payload_schemas(&mut document);
    tighten_scan_config_payload_schemas(&mut document);
    tighten_triage_payload_schemas(&mut document);
    tighten_list_query_parameters(&mut document, "/users");
    tighten_list_query_parameters(&mut document, "/groups");
    tighten_list_query_parameters(&mut document, "/roles");
    tighten_list_query_parameters(&mut document, "/permissions");
    tighten_list_query_parameters(&mut document, "/reports");
    tighten_list_query_parameters(&mut document, "/results");
    tighten_list_query_parameters(&mut document, "/reports/{id}/results");
    tighten_list_query_parameters(&mut document, "/reports/{id}/vulnerabilities");
    tighten_list_query_parameters(&mut document, "/reports/{id}/tls-certificates");
    tighten_list_query_parameters(&mut document, "/reports/{id}/errors");
    tighten_list_query_parameters(&mut document, "/reports/{id}/closed-cves");
    tighten_list_query_parameters(&mut document, "/scan-configs");
    tighten_list_query_parameters(&mut document, "/scanners");
    tighten_report_get_parameters(&mut document);
    tighten_identity_schemas(&mut document);
    ensure_problem_detail_schema(&mut document);
    normalize_problem_response_content_types(&mut document);
    ensure_basic_auth_scheme(&mut document);
    strip_nullable_types(&mut document);
    document
}

fn openapi_tags() -> Value {
    json!([
        {
            "name": "Sessions",
            "description": "Session lifecycle"
        },
        {
            "name": "Targets",
            "description": "Scan target management"
        },
        {
            "name": "Alerts",
            "description": "Alert management"
        },
        {
            "name": "Schedules",
            "description": "Schedule management"
        },
        {
            "name": "Credentials",
            "description": "Credential management"
        },
        {
            "name": "Port Lists",
            "description": "Port list management"
        },
        {
            "name": "Feeds",
            "description": "Feed status"
        },
        {
            "name": "Hosts",
            "description": "Discovered host inventory"
        },
        {
            "name": "Report Formats",
            "description": "Report export format discovery"
        },
        {
            "name": "Filters",
            "description": "Saved filter discovery"
        },
        {
            "name": "Tags",
            "description": "Tag discovery"
        },
        {
            "name": "Tickets",
            "description": "Ticket discovery"
        },
        {
            "name": "Notes",
            "description": "Note discovery"
        },
        {
            "name": "Overrides",
            "description": "Override discovery"
        },
        {
            "name": "NVTs",
            "description": "NVT catalog discovery"
        },
        {
            "name": "NVT Families",
            "description": "NVT family discovery"
        },
        {
            "name": "Users",
            "description": "User management"
        },
        {
            "name": "Groups",
            "description": "Group management"
        },
        {
            "name": "Roles",
            "description": "Role management"
        },
        {
            "name": "Permissions",
            "description": "Permission management"
        },
        {
            "name": "User Settings",
            "description": "Current-user settings"
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
    ])
}

fn synchronize_report_export_responses(paths: &mut Map<String, Value>) {
    let Some(responses) = paths
        .get_mut("/reports/{id}/export")
        .and_then(|path| path.get_mut("get"))
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    responses.insert(
        "200".to_string(),
        json!({
            "description": "Rendered report bytes for the selected report format.",
            "headers": {
                "traceparent": {
                    "description": "W3C Trace Context traceparent header for distributed tracing.",
                    "schema": { "type": "string" }
                },
                "Content-Disposition": {
                    "description": "Attachment-style filename for the rendered report artifact.",
                    "schema": { "type": "string" }
                }
            },
            "content": {
                "application/pdf": { "schema": { "type": "string", "format": "binary" } },
                "application/xml": { "schema": { "type": "string", "format": "binary" } },
                "text/csv": { "schema": { "type": "string", "format": "binary" } },
                "text/plain": { "schema": { "type": "string", "format": "binary" } },
                "image/svg+xml": { "schema": { "type": "string", "format": "binary" } },
                "application/octet-stream": {
                    "schema": { "type": "string", "format": "binary" }
                }
            }
        }),
    );
}

fn apply_route_auth_security(document: &mut Value) {
    let Some(paths) = document["paths"].as_object_mut() else {
        return;
    };

    for (openapi_path, methods) in paths {
        let runtime_path = runtime_path_from_openapi_path(openapi_path);
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };

        for (method_name, operation) in methods {
            let Some(operation) = operation.as_object_mut() else {
                continue;
            };
            let Some(method) = openapi_method(method_name) else {
                continue;
            };
            let Some(policy) = classify_runtime_route(&method, &runtime_path) else {
                continue;
            };

            match policy {
                RestRouteAuthPolicy::Protected => {
                    operation.remove("security");
                }
                RestRouteAuthPolicy::Public => {
                    operation.insert("security".to_string(), json!([]));
                }
                RestRouteAuthPolicy::SessionCreate => {
                    operation.insert("security".to_string(), json!([{"basicAuth": []}]));
                }
                RestRouteAuthPolicy::SessionCurrent => {
                    operation.insert("security".to_string(), json!([{"bearerAuth": []}]));
                }
            }
        }
    }
}

fn openapi_method(method_name: &str) -> Option<Method> {
    Some(match method_name {
        "get" => Method::GET,
        "post" => Method::POST,
        "put" => Method::PUT,
        "delete" => Method::DELETE,
        "patch" => Method::PATCH,
        "options" => Method::OPTIONS,
        "head" => Method::HEAD,
        _ => return None,
    })
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
            match parameter["name"].as_str() {
                Some("ignorePagination") => {
                    parameter["schema"]["default"] = json!(false);
                }
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

fn tighten_alert_payload_schemas(document: &mut Value) {
    if let Some(schema) = document["components"]["schemas"].get_mut("CreateAlert") {
        schema["required"] = json!(["name", "event", "condition", "method"]);
        schema["properties"]["filterId"]["format"] = json!("uuid");
    }
    if let Some(schema) = document["components"]["schemas"].get_mut("ModifyAlert") {
        schema["properties"]["filterId"]["format"] = json!("uuid");
    }
}

fn tighten_schedule_payload_schemas(document: &mut Value) {
    if let Some(schema) = document["components"]["schemas"].get_mut("CreateSchedule") {
        schema["required"] = json!(["name", "icalendar", "timezone"]);
    }
}

fn tighten_credential_payload_schemas(document: &mut Value) {
    if let Some(schema) = document["components"]["schemas"].get_mut("CreateCredential") {
        schema["required"] = json!(["name", "type"]);
        schema["properties"]["password"]["format"] = json!("password");
        schema["properties"]["privacyPassword"]["format"] = json!("password");
    }
    if let Some(schema) = document["components"]["schemas"].get_mut("ModifyCredential") {
        schema["properties"]["password"]["format"] = json!("password");
        schema["properties"]["privacyPassword"]["format"] = json!("password");
    }
}

fn tighten_port_list_payload_schemas(document: &mut Value) {
    if let Some(schema) = document["components"]["schemas"].get_mut("CreatePortList") {
        schema["required"] = json!(["name"]);
    }
}

fn tighten_alert_enums(document: &mut Value) {
    let event_values = json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]);
    let condition_values = json!([
        "always",
        "filter_count_at_least",
        "filter_count_changed",
        "severity_at_least",
        "severity_changed"
    ]);
    let method_values = json!([
        "email",
        "http_get",
        "scp",
        "send_email",
        "smb",
        "snmp",
        "sourcefire_connector",
        "start_task",
        "syslog",
        "tippingpoint",
        "verinice_ce",
        "verinice_net",
        "alemba"
    ]);
    for schema_name in ["Alert", "CreateAlert"] {
        if let Some(schema) = document["components"]["schemas"].get_mut(schema_name) {
            set_open_enum_values(&mut schema["properties"]["event"], event_values.clone());
            set_open_enum_values(
                &mut schema["properties"]["condition"],
                condition_values.clone(),
            );
            set_open_enum_values(&mut schema["properties"]["method"], method_values.clone());
        }
    }
    if let Some(schema) = document["components"]["schemas"].get_mut("Alert") {
        schema["required"] = json!(["id", "name", "event", "condition", "method"]);
    }
}

fn tighten_credential_enums(document: &mut Value) {
    let credential_types = json!(["cc", "pw", "snmp", "snmpv3", "up", "usk"]);
    let auth_algorithms = json!(["md5", "sha1"]);
    let privacy_algorithms = json!(["aes", "des"]);
    if let Some(schema) = document["components"]["schemas"].get_mut("Credential") {
        set_open_enum_values(&mut schema["properties"]["type"], credential_types.clone());
        schema["required"] = json!(["id", "name", "type"]);
    }
    if let Some(schema) = document["components"]["schemas"].get_mut("CreateCredential") {
        set_open_enum_values(&mut schema["properties"]["type"], credential_types);
        schema["properties"]["authAlgorithm"]["enum"] = auth_algorithms.clone();
        schema["properties"]["privacyAlgorithm"]["enum"] = privacy_algorithms.clone();
    }
    if let Some(schema) = document["components"]["schemas"].get_mut("ModifyCredential") {
        schema["properties"]["authAlgorithm"]["enum"] = auth_algorithms;
        schema["properties"]["privacyAlgorithm"]["enum"] = privacy_algorithms;
    }
}

fn tighten_feed_schema(document: &mut Value) {
    if let Some(schema) = document["components"]["schemas"].get_mut("Feed") {
        schema["required"] = json!(["type", "name", "version"]);
        set_open_enum_values(
            &mut schema["properties"]["type"],
            json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
        );
    }
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

fn tighten_scan_config_payload_schemas(document: &mut Value) {
    // `CreateScanConfigRequest.name` is `Option<String>` at runtime (for graceful validation),
    // so schemars omits it from `required`. Inject it here to keep the contract intact.
    if let Some(schema) = document["components"]["schemas"].get_mut("CreateScanConfig") {
        schema["required"] = json!(["name"]);
    }
}

fn tighten_triage_payload_schemas(document: &mut Value) {
    // Create request DTOs keep `nvtOid` optional at runtime so validation can
    // return RFC 9457 problem details. The public schema requires it.
    for schema_name in ["CreateNote", "CreateOverride"] {
        if let Some(schema) = document["components"]["schemas"].get_mut(schema_name) {
            schema["required"] = json!(["nvtOid"]);
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

fn tighten_identity_schemas(document: &mut Value) {
    let schemas = &mut document["components"]["schemas"];
    schemas["IdentityResourceBase"] = json!({
        "type": "object",
        "required": ["id", "name", "writable", "inUse"],
        "properties": {
            "id": {
                "type": "string",
                "format": "uuid"
            },
            "name": {
                "type": "string"
            },
            "comment": {
                "type": "string"
            },
            "owner": {
                "$ref": "#/components/schemas/ResourceRef"
            },
            "creationTime": {
                "type": "string",
                "format": "date-time"
            },
            "modificationTime": {
                "type": "string",
                "format": "date-time"
            },
            "writable": {
                "type": "boolean"
            },
            "inUse": {
                "type": "boolean"
            }
        }
    });

    schemas["User"] = json!({
        "allOf": [
            {
                "$ref": "#/components/schemas/IdentityResourceBase"
            },
            {
                "type": "object",
                "properties": {
                    "roles": {
                        "type": "array",
                        "items": {
                            "$ref": "#/components/schemas/ResourceRef"
                        }
                    },
                    "groups": {
                        "type": "array",
                        "items": {
                            "$ref": "#/components/schemas/ResourceRef"
                        }
                    },
                    "hostsAllow": {
                        "type": "boolean"
                    },
                    "hosts": {
                        "type": "string"
                    },
                    "authenticationType": {
                        "type": "string",
                        "enum": ["file", "ldap_connect", "radius_connect"]
                    }
                }
            }
        ]
    });
    document_open_enum_schema(&mut schemas["User"]["allOf"][1]["properties"]["authenticationType"]);

    schemas["Group"] = json!({
        "allOf": [
            {
                "$ref": "#/components/schemas/IdentityResourceBase"
            },
            {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                }
            }
        ]
    });

    schemas["Role"] = json!({
        "allOf": [
            {
                "$ref": "#/components/schemas/IdentityResourceBase"
            },
            {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                }
            }
        ]
    });

    schemas["Permission"] = json!({
        "allOf": [
            {
                "$ref": "#/components/schemas/IdentityResourceBase"
            },
            {
                "type": "object",
                "properties": {
                    "subjectType": {
                        "type": "string",
                        "enum": ["user", "group", "role"]
                    },
                    "subject": {
                        "$ref": "#/components/schemas/ResourceRef"
                    },
                    "resourceType": {
                        "type": "string"
                    },
                    "resource": {
                        "$ref": "#/components/schemas/ResourceRef"
                    }
                }
            }
        ]
    });

    if let Some(schema) = schemas.get_mut("UserSetting") {
        schema["required"] = json!(["id", "name"]);
    }
    if let Some(schema) = schemas.get_mut("CreateUser") {
        schema["properties"]["password"]["format"] = json!("password");
    }
    if let Some(schema) = schemas.get_mut("ModifyUser") {
        schema["properties"]["password"]["format"] = json!("password");
    }
}

fn set_open_enum_values(schema: &mut Value, values: Value) {
    schema["enum"] = values;
    document_open_enum_schema(schema);
}

fn ensure_problem_detail_schema(document: &mut Value) {
    let schemas = document["components"]["schemas"]
        .as_object_mut()
        .expect("generated OpenAPI document must contain components.schemas");

    schemas.insert(
        "ProblemDetail".to_string(),
        json!({
            "type": "object",
            "required": ["type", "code", "title", "status"],
            "properties": {
                "type": {
                    "type": "string",
                    "format": "uri"
                },
                "code": {
                    "type": "string"
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

fn document_backend_unavailable_responses(paths: &mut Map<String, Value>) {
    for (path, methods) in paths {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method_name, operation) in methods {
            if openapi_method(method_name).is_none() {
                continue;
            }
            if !operation_can_proxy_to_backend(path, method_name, operation) {
                continue;
            }
            let Some(responses) = operation["responses"].as_object_mut() else {
                continue;
            };
            responses
                .entry("502".to_string())
                .or_insert_with(bad_gateway_response);
        }
    }
}

fn operation_can_proxy_to_backend(path: &str, method_name: &str, operation: &Value) -> bool {
    if matches!((path, method_name), ("/session", "get" | "delete")) {
        return false;
    }

    path == "/ready" || operation["responses"].get("401").is_some()
}

fn bad_gateway_response() -> Value {
    json!({
        "description": "Backend service unreachable or connection failed",
        "content": {
            "application/problem+json": {
                "schema": {
                    "$ref": "#/components/schemas/ProblemDetail"
                },
                "example": ProblemDetailDoc::example()
            }
        }
    })
}

fn normalize_problem_response_content_types(document: &mut Value) {
    let Some(paths) = document["paths"].as_object_mut() else {
        return;
    };

    for methods in paths.values_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method_name, operation) in methods {
            if openapi_method(method_name).is_none() {
                continue;
            }
            let Some(responses) = operation["responses"].as_object_mut() else {
                continue;
            };
            for response in responses.values_mut() {
                let Some(content) = response["content"].as_object_mut() else {
                    continue;
                };
                let Some(problem_json) = content.remove("application/json") else {
                    continue;
                };
                let Some(schema_ref) = problem_json["schema"]["$ref"].as_str() else {
                    content.insert("application/json".to_string(), problem_json);
                    continue;
                };
                if schema_ref.ends_with("/ProblemDetail") {
                    content.insert("application/problem+json".to_string(), problem_json);
                } else {
                    content.insert("application/json".to_string(), problem_json);
                }
            }
        }
    }
}

fn ensure_basic_auth_scheme(document: &mut Value) {
    if let Some(security_schemes) = document["components"]["securitySchemes"].as_object_mut() {
        security_schemes.insert(
            "basicAuth".to_string(),
            json!({
                "type": "http",
                "scheme": "basic",
                "description": "HTTP Basic credentials used either to create a persistent session or to authenticate one protected request with request-scoped backend cleanup."
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

fn normalize_paths(source_paths: &Map<String, Value>) -> Map<String, Value> {
    source_paths
        .iter()
        .map(|(source_path, path_item)| {
            let normalized_path = source_path.strip_prefix("/api/v1").map_or_else(
                || source_path.clone(),
                |suffix| {
                    if suffix.is_empty() {
                        "/".to_string()
                    } else {
                        suffix.to_string()
                    }
                },
            );
            (normalized_path, path_item.clone())
        })
        .collect()
}

fn add_probe_server_overrides(normalized_paths: &mut Map<String, Value>) {
    let servers = json!([
        {
            "url": "/",
            "description": "Root path for unversioned liveness and readiness probes"
        }
    ]);

    for path in ["/health", "/ready"] {
        if let Some(path_item) = normalized_paths
            .get_mut(path)
            .and_then(Value::as_object_mut)
        {
            path_item.insert("servers".to_string(), servers.clone());
        }
    }
}

fn add_location_header_to_created_response(normalized_paths: &mut Map<String, Value>, path: &str) {
    if let Some(response) = normalized_paths
        .get_mut(path)
        .and_then(|path_item| path_item.get_mut("post"))
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(|responses| responses.get_mut("201"))
    {
        response["headers"]["Location"] = json!({
            "description": "Canonical URI of the created resource.",
            "schema": {
                "type": "string",
                "format": "uri-reference"
            }
        });
    }
}

fn add_retry_after_header_to_too_many_requests_response(
    normalized_paths: &mut Map<String, Value>,
    path: &str,
) {
    if let Some(response) = normalized_paths
        .get_mut(path)
        .and_then(|path_item| path_item.get_mut("post"))
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(|responses| responses.get_mut("429"))
    {
        response["headers"]["Retry-After"] = json!({
            "description": "Seconds to wait before retrying",
            "schema": {
                "type": "integer"
            }
        });
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
pub(crate) struct ProblemDetailDoc {
    #[serde(rename = "type")]
    r#type: String,
    code: String,
    title: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
}

impl ProblemDetailDoc {
    fn example() -> Self {
        Self {
            r#type: "https://gvm-gateway.greenbone.net/errors/bad-request".to_string(),
            code: "bad_request".to_string(),
            title: "Bad Request".to_string(),
            status: 400,
            detail: Some("request validation failed".to_string()),
            instance: Some("/api/v1/targets".to_string()),
        }
    }
}

// -- Shared path/query parameter schemas -------------------------------------

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ResourceIdPathDoc {
    id: Uuid,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct TargetListQueryDoc {
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
pub(crate) struct CreateTargetDoc {
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
pub(crate) struct ModifyTargetDoc {
    name: Option<String>,
    comment: Option<String>,
    hosts: Option<Vec<String>>,
    #[serde(rename = "excludeHosts")]
    exclude_hosts: Option<Vec<String>>,
    #[serde(rename = "aliveTest")]
    alive_test: Option<AliveTestDoc>,
    #[serde(rename = "portListId")]
    port_list_id: Option<Uuid>,
    /// SSH credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "sshCredentialId")]
    ssh_credential_id: Option<Uuid>,
    /// SMB credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "smbCredentialId")]
    smb_credential_id: Option<Uuid>,
    /// ESXi credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "esxiCredentialId")]
    esxi_credential_id: Option<Uuid>,
    /// SNMP credential binding. Omitted or null leaves the binding unchanged;
    /// clearing credential bindings is not supported by this request shape.
    #[serde(rename = "snmpCredentialId")]
    snmp_credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) enum AliveTestDoc {
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
pub(crate) struct TaskListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateTask")]
pub(crate) struct CreateTaskDoc {
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
pub(crate) struct ModifyTaskDoc {
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
    /// Key-value scan preferences. Omitted or empty objects leave preferences
    /// unchanged; clearing preferences is not supported by this request shape.
    preferences: Option<std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub(crate) enum HostsOrderingDoc {
    #[serde(rename = "sequential")]
    Sequential,
    #[serde(rename = "random")]
    Random,
    #[serde(rename = "reverse")]
    Reverse,
}

// -- Report / result query schemas -------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ReportListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct GetReportQueryDoc {
    #[serde(rename = "ignorePagination")]
    ignore_pagination: Option<bool>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ReportExportQueryDoc {
    #[serde(rename = "reportFormatId")]
    report_format_id: Uuid,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ReportResultsQueryDoc {
    filter: Option<String>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ResultListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
}

// -- Scan config query schema ------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub(crate) struct ScanConfigListQueryDoc {
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
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use serde_json::{json, Map, Value};

    use super::{normalize_paths, openapi_method};
    use crate::auth_policy::{
        classify_runtime_route, runtime_path_from_openapi_path, RestRouteAuthPolicy,
    };
    use crate::router::build_openapi;

    #[test]
    fn generated_openapi_matches_curated_spec() {
        let generated = build_openapi();
        let curated = root_spec();
        let generated_routes = route_methods(&generated);
        let curated_routes = curated_route_methods(&curated);

        assert_route_methods_match(
            &generated_routes,
            &curated_routes,
            "generated OpenAPI route/method set must match the complete curated spec",
        );

        for (generated_path, method) in curated_routes {
            let generated_path_item = &generated["paths"][&generated_path];
            let curated_path_item = resolve_curated_path_item(&curated["paths"][&generated_path]);
            assert_eq!(
                generated_path_item.get("servers"),
                curated_path_item.get("servers"),
                "path-level servers drift for {generated_path}"
            );

            let generated_op = op(&generated, &generated_path, &method);
            let curated_op = &curated_path_item[&method];
            assert_eq!(
                generated_op["operationId"], curated_op["operationId"],
                "operationId drift for {method} {generated_path}"
            );

            let generated_statuses = response_statuses(generated_op);
            let curated_statuses = response_statuses(curated_op);
            assert_string_sets_match(
                &generated_statuses,
                &curated_statuses,
                &format!("generated response status drift for {method} {generated_path}"),
            );
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

        let modify_target_props = &generated["components"]["schemas"]["ModifyTarget"]["properties"];
        assert!(modify_target_props.get("sshCredentialId").is_some());
        assert!(modify_target_props.get("smbCredentialId").is_some());
        assert!(modify_target_props.get("esxiCredentialId").is_some());
        assert!(modify_target_props.get("snmpCredentialId").is_some());

        let modify_task_props = &generated["components"]["schemas"]["ModifyTask"]["properties"];
        assert!(modify_task_props.get("preferences").is_some());
        let preferences_description = modify_task_props["preferences"]["description"]
            .as_str()
            .expect("ModifyTask.preferences should document update semantics");
        assert!(preferences_description.contains("Omitted or empty objects"));
        assert!(preferences_description.contains("clearing preferences is not supported"));

        let schemas = &generated["components"]["schemas"];
        assert_empty_array_modify_limitation(
            &schemas["UpdateNote"]["properties"]["hosts"],
            "UpdateNote.hosts",
            "clearing all hosts",
        );
        assert_empty_array_modify_limitation(
            &schemas["UpdateOverride"]["properties"]["hosts"],
            "UpdateOverride.hosts",
            "clearing all hosts",
        );
        assert_empty_array_modify_limitation(
            &schemas["ModifyUser"]["properties"]["roles"],
            "ModifyUser.roles",
            "clearing all roles",
        );
    }

    #[test]
    fn generated_openapi_feed_version_matches_required_runtime_contract() {
        let generated = build_openapi();
        let required = generated["components"]["schemas"]["Feed"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();

        assert!(required.contains("type"));
        assert!(required.contains("name"));
        assert!(required.contains("version"));
    }

    #[test]
    fn generated_openapi_documents_open_enum_fields_as_non_exhaustive() {
        let generated = build_openapi();
        let schemas = &generated["components"]["schemas"];

        // Open enums deliberately keep OpenAPI enum lists for docs/codegen while
        // their descriptions define the non-exhaustive runtime contract.
        assert_open_enum_schema(
            &schemas["CredentialType"],
            json!(["cc", "pw", "snmp", "snmpv3", "up", "usk"]),
            "CredentialType",
        );
        assert_open_enum_schema(
            &schemas["FeedType"],
            json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
            "FeedType",
        );
        assert_open_enum_schema(
            &schemas["AlertEvent"],
            json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
            "AlertEvent",
        );
        assert_open_enum_schema(
            &schemas["AlertCondition"],
            json!([
                "always",
                "filter_count_at_least",
                "filter_count_changed",
                "severity_at_least",
                "severity_changed"
            ]),
            "AlertCondition",
        );
        assert_open_enum_schema(
            &schemas["AlertMethod"],
            json!([
                "email",
                "http_get",
                "scp",
                "send_email",
                "smb",
                "snmp",
                "sourcefire_connector",
                "start_task",
                "syslog",
                "tippingpoint",
                "verinice_ce",
                "verinice_net",
                "alemba"
            ]),
            "AlertMethod",
        );
        assert_open_enum_schema(
            &schemas["AuthenticationType"],
            json!(["file", "ldap_connect", "radius_connect"]),
            "AuthenticationType",
        );
        assert_open_enum_schema(&schemas["ScanConfigType"], json!([0, 1]), "ScanConfigType");
        assert_open_enum_schema(
            &schemas["TicketStatus"],
            json!(["Open", "Fixed", "Closed"]),
            "TicketStatus",
        );

        let alert_props = &schemas["Alert"]["properties"];
        assert_open_enum_schema(
            &alert_props["event"],
            json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
            "Alert.event",
        );
        assert_open_enum_schema(
            &alert_props["condition"],
            json!([
                "always",
                "filter_count_at_least",
                "filter_count_changed",
                "severity_at_least",
                "severity_changed"
            ]),
            "Alert.condition",
        );
        assert_open_enum_schema(
            &alert_props["method"],
            json!([
                "email",
                "http_get",
                "scp",
                "send_email",
                "smb",
                "snmp",
                "sourcefire_connector",
                "start_task",
                "syslog",
                "tippingpoint",
                "verinice_ce",
                "verinice_net",
                "alemba"
            ]),
            "Alert.method",
        );

        let create_alert_props = &schemas["CreateAlert"]["properties"];
        assert_open_enum_schema(
            &create_alert_props["event"],
            json!(["task_run_status_changed", "updated_secinfo", "new_secinfo"]),
            "CreateAlert.event",
        );
        assert_open_enum_schema(
            &create_alert_props["condition"],
            json!([
                "always",
                "filter_count_at_least",
                "filter_count_changed",
                "severity_at_least",
                "severity_changed"
            ]),
            "CreateAlert.condition",
        );
        assert_open_enum_schema(
            &create_alert_props["method"],
            json!([
                "email",
                "http_get",
                "scp",
                "send_email",
                "smb",
                "snmp",
                "sourcefire_connector",
                "start_task",
                "syslog",
                "tippingpoint",
                "verinice_ce",
                "verinice_net",
                "alemba"
            ]),
            "CreateAlert.method",
        );

        assert_open_enum_schema(
            &schemas["Credential"]["properties"]["type"],
            json!(["cc", "pw", "snmp", "snmpv3", "up", "usk"]),
            "Credential.type",
        );
        assert_open_enum_schema(
            &schemas["CreateCredential"]["properties"]["type"],
            json!(["cc", "pw", "snmp", "snmpv3", "up", "usk"]),
            "CreateCredential.type",
        );
        assert_open_enum_schema(
            &schemas["Feed"]["properties"]["type"],
            json!(["NVT", "CERT", "SCAP", "GVMD_DATA"]),
            "Feed.type",
        );
        assert_open_enum_schema(
            &schemas["User"]["allOf"][1]["properties"]["authenticationType"],
            json!(["file", "ldap_connect", "radius_connect"]),
            "User.authenticationType",
        );
    }

    #[test]
    fn generated_openapi_declares_every_operation_tag() {
        let generated = build_openapi();
        let declared_tags = generated["tags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tag| tag["name"].as_str())
            .collect::<BTreeSet<_>>();

        for (path, methods) in generated["paths"].as_object().unwrap() {
            for (method, operation) in methods.as_object().unwrap() {
                if openapi_method(method).is_none() {
                    continue;
                }
                for tag in operation["tags"].as_array().into_iter().flatten() {
                    let tag = tag.as_str().unwrap();
                    assert!(
                        declared_tags.contains(tag),
                        "missing top-level tag declaration for {tag} used by {method} {path}"
                    );
                }
            }
        }
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
    fn generated_openapi_session_state_matches_inspectable_contract() {
        let generated = build_openapi();
        let schemas = &generated["components"]["schemas"];

        assert_eq!(
            schemas["SessionInfo"]["properties"]["state"]["$ref"],
            json!("#/components/schemas/SessionState")
        );
        assert_eq!(
            schemas["SessionState"]["enum"],
            json!(["active", "expired"]),
            "SessionInfo state must only document states returned by GET /session"
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

    #[test]
    fn generated_openapi_applies_route_auth_policy_consistently() {
        let generated = build_openapi();

        for (path, method_name) in route_methods(&generated) {
            let method =
                openapi_method(&method_name).expect("route_methods returns valid HTTP methods");
            let runtime_path = runtime_path_from_openapi_path(&path);
            let operation = op(&generated, &path, &method_name);
            let policy = classify_runtime_route(&method, &runtime_path)
                .unwrap_or_else(|| panic!("missing auth policy for {method_name} {path}"));

            match policy {
                RestRouteAuthPolicy::Public => {
                    assert_eq!(
                        operation["security"],
                        json!([]),
                        "{method_name} {path} should explicitly disable auth"
                    );
                }
                RestRouteAuthPolicy::SessionCreate => {
                    assert_eq!(
                        operation["security"],
                        json!([{"basicAuth": []}]),
                        "{method_name} {path} should require Basic auth"
                    );
                }
                RestRouteAuthPolicy::SessionCurrent => {
                    assert_eq!(
                        operation["security"],
                        json!([{"bearerAuth": []}]),
                        "{method_name} {path} should require Bearer auth"
                    );
                }
                RestRouteAuthPolicy::Protected => {
                    assert!(
                        operation.get("security").is_none(),
                        "{method_name} {path} should inherit dual protected-route auth"
                    );
                }
            }
        }
    }

    #[test]
    fn normalize_paths_strips_runtime_api_prefix() {
        let source_paths = serde_json::from_value::<Map<String, Value>>(serde_json::json!({
            "/health": { "get": {} },
            "/ready": { "get": {} },
            "/api/v1/version": { "get": {} },
            "/api/v1/reports/{id}/export": { "get": {} }
        }))
        .unwrap();

        let normalized = normalize_paths(&source_paths);

        assert!(normalized.contains_key("/health"));
        assert!(normalized.contains_key("/ready"));
        assert!(normalized.contains_key("/version"));
        assert!(normalized.contains_key("/reports/{id}/export"));
        assert!(!normalized.contains_key("/api/v1/version"));
        assert!(!normalized.contains_key("/api/v1/reports/{id}/export"));
    }

    fn root_spec() -> Value {
        read_yaml(&root_spec_path())
    }

    fn curated_route_methods(root_spec: &Value) -> BTreeSet<(String, String)> {
        root_spec["paths"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(path, path_item_ref)| {
                operation_methods(&resolve_curated_path_item(path_item_ref))
                    .into_iter()
                    .map(move |method| (path.clone(), method))
            })
            .collect()
    }

    fn route_methods(doc: &Value) -> BTreeSet<(String, String)> {
        doc["paths"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(path, path_item)| {
                operation_methods(path_item)
                    .into_iter()
                    .map(move |method| (path.clone(), method))
            })
            .collect()
    }

    fn assert_route_methods_match(
        generated: &BTreeSet<(String, String)>,
        curated: &BTreeSet<(String, String)>,
        context: &str,
    ) {
        let generated_only = generated.difference(curated).collect::<Vec<_>>();
        let curated_only = curated.difference(generated).collect::<Vec<_>>();

        assert!(
            generated_only.is_empty() && curated_only.is_empty(),
            "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
        );
    }

    fn assert_string_sets_match(
        generated: &BTreeSet<&str>,
        curated: &BTreeSet<&str>,
        context: &str,
    ) {
        let generated_only = generated.difference(curated).collect::<Vec<_>>();
        let curated_only = curated.difference(generated).collect::<Vec<_>>();

        assert!(
            generated_only.is_empty() && curated_only.is_empty(),
            "{context}: generated_only={generated_only:?}, curated_only={curated_only:?}"
        );
    }

    fn operation_methods(path_item: &Value) -> Vec<String> {
        path_item
            .as_object()
            .unwrap()
            .keys()
            .filter(|method| openapi_method(method).is_some())
            .cloned()
            .collect()
    }

    fn resolve_curated_path_item(path_item_ref: &Value) -> Value {
        let reference = path_item_ref["$ref"]
            .as_str()
            .expect("root spec path items should use file refs");

        resolve_spec_ref(&root_spec_path(), reference)
    }

    fn resolve_spec_ref(current_doc_path: &Path, reference: &str) -> Value {
        let (doc_ref, pointer) = reference
            .split_once('#')
            .unwrap_or_else(|| panic!("path item ref `{reference}` should include a JSON pointer"));
        let doc_path = if doc_ref.is_empty() {
            current_doc_path.to_path_buf()
        } else {
            current_doc_path
                .parent()
                .expect("spec document should have a parent directory")
                .join(doc_ref)
        };

        read_yaml(&doc_path)
            .pointer(pointer)
            .unwrap_or_else(|| panic!("missing path item ref target `{reference}`"))
            .clone()
    }

    fn root_spec_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/rest-api/openapi.yaml")
    }

    fn read_yaml(path: &Path) -> Value {
        let source = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", path.display()));
        serde_yaml::from_str(&source)
            .unwrap_or_else(|error| panic!("failed to parse `{}`: {error}", path.display()))
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

    fn assert_open_enum_schema(schema: &Value, expected_values: Value, context: &str) {
        assert_eq!(
            schema["enum"], expected_values,
            "{context} should list known values for OpenAPI docs and client generation"
        );

        let description = schema["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{context} should describe the open-enum contract"));
        assert!(
            description.contains("This list is not exhaustive"),
            "{context} should document that known enum values are non-exhaustive"
        );
        assert!(
            description.contains("unknown future values"),
            "{context} should document future backend values"
        );
        assert!(
            description.contains("clients must preserve them"),
            "{context} should document client preservation of unknown values"
        );
    }

    fn assert_empty_array_modify_limitation(schema: &Value, context: &str, clear_phrase: &str) {
        let description = schema["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{context} should document empty-array update semantics"));
        for phrase in [
            "Omitted",
            "null",
            "empty arrays",
            "leave existing",
            clear_phrase,
        ] {
            assert!(
                description.contains(phrase),
                "{context} description should mention {phrase:?}; description={description:?}"
            );
        }
    }
}
