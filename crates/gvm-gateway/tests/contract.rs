mod common;

use std::collections::BTreeSet;

use common::spawn_server;
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::targets::{
    build_gmp_filter, CreateTargetRequest, ModifyTargetRequest, TargetListQuery,
};
use http::StatusCode;
use reqwest::Client;
use serde_json::Value;

#[tokio::test]
async fn generated_openapi_endpoint_exposes_implemented_contract() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/json"
    );

    let json = response.json::<Value>().await.unwrap();
    let root_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/openapi.yaml")).unwrap();
    let system_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/system.yaml")).unwrap();
    let sessions_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/sessions.yaml")).unwrap();
    let targets_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/targets.yaml")).unwrap();
    let tasks_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/tasks.yaml")).unwrap();
    let reports_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/reports.yaml")).unwrap();
    let results_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/results.yaml")).unwrap();
    let alerts_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/alerts.yaml")).unwrap();
    let schedules_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/schedules.yaml")).unwrap();
    let credentials_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/credentials.yaml")).unwrap();
    let port_lists_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/port-lists.yaml")).unwrap();
    let feeds_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/feeds.yaml")).unwrap();
    let supporting_resources_spec: Value = serde_yaml::from_str(include_str!(
        "../../../spec/rest-api/supporting-resources.yaml"
    ))
    .unwrap();
    let identity_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/identity.yaml")).unwrap();
    let scan_configs_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/scan-configs.yaml")).unwrap();
    let scanners_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/scanners.yaml")).unwrap();
    let common_spec: Value =
        serde_yaml::from_str(include_str!("../../../spec/rest-api/common.yaml")).unwrap();

    let docs = SpecDocs {
        generated: &json,
        system: &system_spec,
        sessions: &sessions_spec,
        targets: &targets_spec,
        tasks: &tasks_spec,
        reports: &reports_spec,
        results: &results_spec,
        alerts: &alerts_spec,
        schedules: &schedules_spec,
        credentials: &credentials_spec,
        port_lists: &port_lists_spec,
        feeds: &feeds_spec,
        supporting_resources: &supporting_resources_spec,
        identity: &identity_spec,
        scan_configs: &scan_configs_spec,
        scanners: &scanners_spec,
        common: &common_spec,
    };

    assert_eq!(json["servers"], root_spec["servers"]);
    assert_eq!(json["security"], root_spec["security"]);
    assert_eq!(
        path_names(&json),
        BTreeSet::from([
            "/health",
            "/alerts",
            "/alerts/{id}",
            "/credential-stores",
            "/credentials",
            "/credentials/{id}",
            "/feeds",
            "/feeds/sync",
            "/filters",
            "/filters/{id}",
            "/groups",
            "/groups/{id}",
            "/openapi.json",
            "/permissions",
            "/permissions/{id}",
            "/port-lists",
            "/port-lists/{id}",
            "/ready",
            "/report-formats",
            "/report-formats/{id}",
            "/reports",
            "/reports/{id}",
            "/reports/{id}/closed-cves",
            "/reports/{id}/errors",
            "/reports/{id}/export",
            "/reports/{id}/results",
            "/reports/{id}/tls-certificates",
            "/reports/{id}/vulnerabilities",
            "/results",
            "/results/{id}",
            "/roles",
            "/roles/{id}",
            "/scan-configs",
            "/scan-configs/{id}",
            "/scanners",
            "/scanners/{id}",
            "/schedules",
            "/schedules/{id}",
            "/sessions",
            "/sessions/{token}",
            "/tags",
            "/tags/{id}",
            "/tickets",
            "/tickets/{id}",
            "/targets",
            "/targets/{id}",
            "/tasks",
            "/tasks/{id}",
            "/tasks/{id}/start",
            "/tasks/{id}/stop",
            "/tasks/{id}/resume",
            "/timezones",
            "/user-settings",
            "/user-settings/{id}",
            "/users",
            "/users/{id}",
            "/version",
        ])
    );

    let checks = [
        ("/health", "get", DocName::System, "/health"),
        ("/ready", "get", DocName::System, "/ready"),
        ("/version", "get", DocName::System, "/version"),
        ("/openapi.json", "get", DocName::System, "/openapi.json"),
        ("/sessions", "post", DocName::Sessions, "/sessions"),
        (
            "/sessions/{token}",
            "get",
            DocName::Sessions,
            "/sessions/{token}",
        ),
        (
            "/sessions/{token}",
            "delete",
            DocName::Sessions,
            "/sessions/{token}",
        ),
        ("/targets", "get", DocName::Targets, "/targets"),
        ("/targets", "post", DocName::Targets, "/targets"),
        ("/targets/{id}", "get", DocName::Targets, "/targets/{id}"),
        ("/targets/{id}", "put", DocName::Targets, "/targets/{id}"),
        ("/targets/{id}", "delete", DocName::Targets, "/targets/{id}"),
        ("/alerts", "get", DocName::Alerts, "/alerts"),
        ("/alerts", "post", DocName::Alerts, "/alerts"),
        ("/alerts/{id}", "get", DocName::Alerts, "/alerts/{id}"),
        ("/alerts/{id}", "put", DocName::Alerts, "/alerts/{id}"),
        ("/alerts/{id}", "delete", DocName::Alerts, "/alerts/{id}"),
        ("/timezones", "get", DocName::Schedules, "/timezones"),
        ("/schedules", "get", DocName::Schedules, "/schedules"),
        ("/schedules", "post", DocName::Schedules, "/schedules"),
        (
            "/schedules/{id}",
            "get",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/schedules/{id}",
            "put",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/schedules/{id}",
            "delete",
            DocName::Schedules,
            "/schedules/{id}",
        ),
        (
            "/credential-stores",
            "get",
            DocName::Credentials,
            "/credential-stores",
        ),
        ("/credentials", "get", DocName::Credentials, "/credentials"),
        ("/credentials", "post", DocName::Credentials, "/credentials"),
        (
            "/credentials/{id}",
            "get",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        (
            "/credentials/{id}",
            "put",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        (
            "/credentials/{id}",
            "delete",
            DocName::Credentials,
            "/credentials/{id}",
        ),
        ("/port-lists", "get", DocName::PortLists, "/port-lists"),
        ("/port-lists", "post", DocName::PortLists, "/port-lists"),
        (
            "/port-lists/{id}",
            "get",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        (
            "/port-lists/{id}",
            "put",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        (
            "/port-lists/{id}",
            "delete",
            DocName::PortLists,
            "/port-lists/{id}",
        ),
        ("/feeds", "get", DocName::Feeds, "/feeds"),
        ("/feeds/sync", "post", DocName::Feeds, "/feeds/sync"),
        (
            "/report-formats",
            "get",
            DocName::SupportingResources,
            "/report-formats",
        ),
        (
            "/report-formats/{id}",
            "get",
            DocName::SupportingResources,
            "/report-formats/{id}",
        ),
        ("/filters", "get", DocName::SupportingResources, "/filters"),
        (
            "/filters/{id}",
            "get",
            DocName::SupportingResources,
            "/filters/{id}",
        ),
        ("/tags", "get", DocName::SupportingResources, "/tags"),
        (
            "/tags/{id}",
            "get",
            DocName::SupportingResources,
            "/tags/{id}",
        ),
        ("/tickets", "get", DocName::SupportingResources, "/tickets"),
        (
            "/tickets/{id}",
            "get",
            DocName::SupportingResources,
            "/tickets/{id}",
        ),
        ("/users", "get", DocName::Identity, "/users"),
        ("/users", "post", DocName::Identity, "/users"),
        ("/users/{id}", "get", DocName::Identity, "/users/{id}"),
        ("/users/{id}", "put", DocName::Identity, "/users/{id}"),
        ("/users/{id}", "delete", DocName::Identity, "/users/{id}"),
        ("/groups", "get", DocName::Identity, "/groups"),
        ("/groups", "post", DocName::Identity, "/groups"),
        ("/groups/{id}", "get", DocName::Identity, "/groups/{id}"),
        ("/groups/{id}", "put", DocName::Identity, "/groups/{id}"),
        ("/groups/{id}", "delete", DocName::Identity, "/groups/{id}"),
        ("/roles", "get", DocName::Identity, "/roles"),
        ("/roles", "post", DocName::Identity, "/roles"),
        ("/roles/{id}", "get", DocName::Identity, "/roles/{id}"),
        ("/roles/{id}", "put", DocName::Identity, "/roles/{id}"),
        ("/roles/{id}", "delete", DocName::Identity, "/roles/{id}"),
        ("/permissions", "get", DocName::Identity, "/permissions"),
        ("/permissions", "post", DocName::Identity, "/permissions"),
        (
            "/permissions/{id}",
            "get",
            DocName::Identity,
            "/permissions/{id}",
        ),
        (
            "/permissions/{id}",
            "put",
            DocName::Identity,
            "/permissions/{id}",
        ),
        (
            "/permissions/{id}",
            "delete",
            DocName::Identity,
            "/permissions/{id}",
        ),
        ("/user-settings", "get", DocName::Identity, "/user-settings"),
        (
            "/user-settings/{id}",
            "get",
            DocName::Identity,
            "/user-settings/{id}",
        ),
        (
            "/user-settings/{id}",
            "put",
            DocName::Identity,
            "/user-settings/{id}",
        ),
        ("/tasks", "get", DocName::Tasks, "/tasks"),
        ("/tasks", "post", DocName::Tasks, "/tasks"),
        ("/tasks/{id}", "get", DocName::Tasks, "/tasks/{id}"),
        ("/tasks/{id}", "put", DocName::Tasks, "/tasks/{id}"),
        ("/tasks/{id}", "delete", DocName::Tasks, "/tasks/{id}"),
        (
            "/tasks/{id}/start",
            "post",
            DocName::Tasks,
            "/tasks/{id}/start",
        ),
        (
            "/tasks/{id}/stop",
            "post",
            DocName::Tasks,
            "/tasks/{id}/stop",
        ),
        (
            "/tasks/{id}/resume",
            "post",
            DocName::Tasks,
            "/tasks/{id}/resume",
        ),
        ("/reports", "get", DocName::Reports, "/reports"),
        ("/reports/{id}", "get", DocName::Reports, "/reports/{id}"),
        ("/reports/{id}", "delete", DocName::Reports, "/reports/{id}"),
        (
            "/reports/{id}/export",
            "get",
            DocName::Reports,
            "/reports/{id}/export",
        ),
        (
            "/reports/{id}/results",
            "get",
            DocName::Reports,
            "/reports/{id}/results",
        ),
        (
            "/reports/{id}/vulnerabilities",
            "get",
            DocName::Reports,
            "/reports/{id}/vulnerabilities",
        ),
        (
            "/reports/{id}/tls-certificates",
            "get",
            DocName::Reports,
            "/reports/{id}/tls-certificates",
        ),
        (
            "/reports/{id}/errors",
            "get",
            DocName::Reports,
            "/reports/{id}/errors",
        ),
        (
            "/reports/{id}/closed-cves",
            "get",
            DocName::Reports,
            "/reports/{id}/closed-cves",
        ),
        ("/results", "get", DocName::Results, "/results"),
        ("/results/{id}", "get", DocName::Results, "/results/{id}"),
        (
            "/scan-configs",
            "get",
            DocName::ScanConfigs,
            "/scan-configs",
        ),
        (
            "/scan-configs",
            "post",
            DocName::ScanConfigs,
            "/scan-configs",
        ),
        (
            "/scan-configs/{id}",
            "get",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        (
            "/scan-configs/{id}",
            "put",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        (
            "/scan-configs/{id}",
            "delete",
            DocName::ScanConfigs,
            "/scan-configs/{id}",
        ),
        ("/scanners", "get", DocName::Scanners, "/scanners"),
        ("/scanners/{id}", "get", DocName::Scanners, "/scanners/{id}"),
    ];

    for (generated_path, method, curated_doc, curated_path) in checks {
        assert_operation_contract(&docs, generated_path, method, curated_doc, curated_path);
    }

    handle.abort();
}

#[tokio::test]
async fn trace_context_headers_propagated_without_baggage_echo() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/health"))
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        )
        .header("tracestate", "vendor=value")
        .header("baggage", "user_id=123")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("traceparent").unwrap(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
    );
    assert_eq!(
        response.headers().get("tracestate").unwrap(),
        "vendor=value"
    );
    assert!(response.headers().get("baggage").is_none());

    handle.abort();
}

#[tokio::test]
async fn problem_details_shape_on_error() {
    let adapter = StaticGvmdAdapter::not_ready("backend offline", "22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/api/v1/version"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/bad-gateway")
    );
    assert_eq!(json["code"], serde_json::json!("backend_unavailable"));
    assert_eq!(json["title"], serde_json::json!("Bad Gateway"));
    assert_eq!(json["status"], serde_json::json!(502));
    assert_eq!(json["detail"], serde_json::json!("backend offline"));
    assert_eq!(json["instance"], serde_json::json!("/api/v1/version"));

    handle.abort();
}

#[tokio::test]
async fn not_found_route_returns_404_problem() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let response = Client::new()
        .get(format!("http://{addr}/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        json["type"],
        serde_json::json!("https://gvm-gateway.greenbone.net/errors/not-found")
    );
    assert_eq!(json["code"], serde_json::json!("not_found"));
    assert_eq!(json["title"], serde_json::json!("Not Found"));
    assert_eq!(json["status"], serde_json::json!(404));
    assert_eq!(json["instance"], serde_json::json!("/does-not-exist"));

    handle.abort();
}

#[test]
fn pagination_defaults() {
    let query = TargetListQuery::try_from_query_string("").unwrap();

    assert_eq!(query.page, 1);
    assert_eq!(query.per_page, 25);
}

#[test]
fn pagination_bounds() {
    let query = TargetListQuery::try_from_query_string("perPage=5000").unwrap();

    assert_eq!(query.per_page, 1000);
}

#[test]
fn filter_to_gmp_string() {
    let filter = build_gmp_filter(Some("name=Target-7".to_string()), None);

    assert_eq!(filter.as_deref(), Some("name=Target-7"));
}

#[test]
fn uuid_validation() {
    assert!(TargetListQuery::try_from_query_string("filterId=not-a-uuid").is_err());
    assert!(CreateTargetRequest {
        name: Some("target".to_string()),
        comment: None,
        hosts: vec!["127.0.0.1".to_string()],
        exclude_hosts: vec![],
        alive_test: None,
        port_list_id: Some("not-a-uuid".to_string()),
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        ssh_credential_id: None,
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
    assert!(ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: Some("still-not-a-uuid".to_string()),
    }
    .validate()
    .is_err());
}

#[derive(Clone, Copy)]
enum DocName {
    Generated,
    System,
    Sessions,
    Targets,
    Alerts,
    Schedules,
    Credentials,
    PortLists,
    Feeds,
    SupportingResources,
    Identity,
    Tasks,
    ScanConfigs,
    Scanners,
    Reports,
    Results,
    Common,
}

struct SpecDocs<'a> {
    generated: &'a Value,
    system: &'a Value,
    sessions: &'a Value,
    targets: &'a Value,
    tasks: &'a Value,
    reports: &'a Value,
    results: &'a Value,
    alerts: &'a Value,
    schedules: &'a Value,
    credentials: &'a Value,
    port_lists: &'a Value,
    feeds: &'a Value,
    supporting_resources: &'a Value,
    identity: &'a Value,
    scan_configs: &'a Value,
    scanners: &'a Value,
    common: &'a Value,
}

fn assert_operation_contract(
    docs: &SpecDocs<'_>,
    generated_path: &str,
    method: &str,
    curated_doc: DocName,
    curated_path: &str,
) {
    let generated_op = effective_operation(docs.generated, generated_path, method);
    let curated_op = effective_operation(doc(docs, curated_doc), curated_path, method);
    let context = format!("{method} {generated_path}");

    assert_eq!(
        generated_op["operationId"], curated_op["operationId"],
        "operationId drift for {context}"
    );
    assert_eq!(
        generated_op["tags"], curated_op["tags"],
        "tags drift for {context}"
    );
    assert_eq!(
        generated_op["summary"], curated_op["summary"],
        "summary drift for {context}"
    );

    compare_parameters(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_request_body(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
    compare_responses(
        docs,
        DocName::Generated,
        &generated_op,
        curated_doc,
        &curated_op,
        &context,
    );
}

fn compare_parameters(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_params = generated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let curated_params = curated_op["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_params
        .iter()
        .map(|parameter| parameter_key(docs, generated_doc, parameter))
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_params
        .iter()
        .map(|parameter| parameter_key(docs, curated_doc, parameter))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        generated_keys, curated_keys,
        "parameter set drift for {context}"
    );

    for key in generated_keys {
        let generated_parameter = generated_params
            .iter()
            .find(|parameter| parameter_key(docs, generated_doc, parameter) == key)
            .unwrap();
        let curated_parameter = curated_params
            .iter()
            .find(|parameter| parameter_key(docs, curated_doc, parameter) == key)
            .unwrap();

        let (generated_parameter_doc, generated_parameter) =
            resolve_ref(docs, generated_doc, generated_parameter);
        let (curated_parameter_doc, curated_parameter) =
            resolve_ref(docs, curated_doc, curated_parameter);

        assert_required_flag(
            generated_parameter.get("required"),
            curated_parameter.get("required"),
            &format!("{context} parameter {key} required"),
        );

        compare_schema_like(
            docs,
            generated_parameter_doc,
            generated_parameter.get("schema").unwrap_or(&Value::Null),
            curated_parameter_doc,
            curated_parameter.get("schema").unwrap_or(&Value::Null),
            &format!("{context} parameter {key} schema"),
        );
    }
}

fn compare_request_body(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_body = generated_op
        .get("requestBody")
        .filter(|value| !value.is_null());
    let curated_body = curated_op
        .get("requestBody")
        .filter(|value| !value.is_null());

    match (generated_body, curated_body) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            panic!("requestBody presence drift for {context}");
        }
        (Some(generated_body), Some(curated_body)) => {
            let (generated_body_doc, generated_body) =
                resolve_ref(docs, generated_doc, generated_body);
            let (curated_body_doc, curated_body) = resolve_ref(docs, curated_doc, curated_body);

            assert_required_flag(
                generated_body.get("required"),
                curated_body.get("required"),
                &format!("{context} requestBody required"),
            );

            let generated_content = generated_body["content"].as_object().unwrap();
            let curated_content = curated_body["content"].as_object().unwrap();
            assert_eq!(
                generated_content.keys().collect::<BTreeSet<_>>(),
                curated_content.keys().collect::<BTreeSet<_>>(),
                "requestBody content types drift for {context}"
            );

            for media_type in generated_content.keys() {
                compare_schema_like(
                    docs,
                    generated_body_doc,
                    &generated_content[media_type]["schema"],
                    curated_body_doc,
                    &curated_content[media_type]["schema"],
                    &format!("{context} requestBody {media_type} schema"),
                );
            }
        }
    }
}

fn compare_responses(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_op: &Value,
    curated_doc: DocName,
    curated_op: &Value,
    context: &str,
) {
    let generated_responses = generated_op["responses"].as_object().unwrap();
    let curated_responses = curated_op["responses"].as_object().unwrap();
    let generated_statuses = generated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_statuses = curated_responses
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert!(
        generated_statuses.is_subset(&curated_statuses),
        "response status drift for {context}: generated={generated_statuses:?}, curated={curated_statuses:?}"
    );

    for status in generated_statuses {
        let (generated_response_doc, generated_response) =
            resolve_ref(docs, generated_doc, &generated_responses[status]);
        let (curated_response_doc, curated_response) =
            resolve_ref(docs, curated_doc, &curated_responses[status]);

        let generated_content = generated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let curated_content = curated_response
            .get("content")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let generated_media_types = generated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let curated_media_types = curated_content
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert!(
            generated_media_types.is_subset(&curated_media_types),
            "response content type drift for {context} {status}"
        );
        compare_headers(
            docs,
            generated_response_doc,
            generated_response.get("headers"),
            curated_response_doc,
            curated_response.get("headers"),
            &format!("{context} response {status} headers"),
        );

        for media_type in generated_media_types {
            compare_schema_like(
                docs,
                generated_response_doc,
                &generated_content[media_type]["schema"],
                curated_response_doc,
                &curated_content[media_type]["schema"],
                &format!("{context} response {status} {media_type} schema"),
            );
        }
    }
}

fn compare_headers(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated_headers: Option<&Value>,
    curated_doc: DocName,
    curated_headers: Option<&Value>,
    context: &str,
) {
    let generated_headers = generated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let curated_headers = curated_headers
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let generated_keys = generated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let curated_keys = curated_headers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    assert!(
        generated_keys.is_subset(&curated_keys),
        "response header drift for {context}: generated={generated_keys:?}, curated={curated_keys:?}"
    );

    for key in generated_keys {
        let (generated_header_doc, generated_header) =
            resolve_ref(docs, generated_doc, &generated_headers[key]);
        let (curated_header_doc, curated_header) =
            resolve_ref(docs, curated_doc, &curated_headers[key]);

        assert_required_flag(
            generated_header.get("required"),
            curated_header.get("required"),
            &format!("{context} {key} required"),
        );
        compare_schema_like(
            docs,
            generated_header_doc,
            generated_header.get("schema").unwrap_or(&Value::Null),
            curated_header_doc,
            curated_header.get("schema").unwrap_or(&Value::Null),
            &format!("{context} {key} schema"),
        );
    }
}

fn compare_schema_like(
    docs: &SpecDocs<'_>,
    generated_doc: DocName,
    generated: &Value,
    curated_doc: DocName,
    curated: &Value,
    context: &str,
) {
    let (generated_doc, generated) = resolve_ref(docs, generated_doc, generated);
    let (curated_doc, curated) = resolve_ref(docs, curated_doc, curated);

    match (generated, curated) {
        (Value::Null, Value::Null) => {}
        (_, Value::Null) | (Value::Null, _) => panic!("schema presence drift for {context}"),
        (Value::Object(generated), Value::Object(curated)) => {
            for (key, curated_value) in curated {
                if matches!(
                    key.as_str(),
                    "description" | "example" | "examples" | "title"
                ) {
                    continue;
                }

                let generated_value = generated
                    .get(key)
                    .unwrap_or_else(|| panic!("missing `{key}` in {context}"));

                match key.as_str() {
                    "required" if curated_value.is_boolean() => assert_required_flag(
                        Some(generated_value),
                        Some(curated_value),
                        &format!("{context} required"),
                    ),
                    "required" => assert_required_items(
                        generated_value,
                        curated_value,
                        &format!("{context} required"),
                    ),
                    "enum" => assert_enum_subset(
                        generated_value,
                        curated_value,
                        &format!("{context} enum"),
                    ),
                    "minimum" | "exclusiveMinimum" | "minLength" | "minItems" | "minProperties" => {
                        assert_numeric_at_least(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    "maximum" | "exclusiveMaximum" | "maxLength" | "maxItems" | "maxProperties" => {
                        assert_numeric_at_most(
                            generated_value,
                            curated_value,
                            &format!("{context} {key}"),
                        )
                    }
                    _ => compare_schema_like(
                        docs,
                        generated_doc,
                        generated_value,
                        curated_doc,
                        curated_value,
                        &format!("{context}.{key}"),
                    ),
                }
            }
        }
        (Value::Array(generated), Value::Array(curated)) => {
            assert_eq!(
                generated.len(),
                curated.len(),
                "array length drift for {context}"
            );
            for (index, (generated_value, curated_value)) in
                generated.iter().zip(curated).enumerate()
            {
                compare_schema_like(
                    docs,
                    generated_doc,
                    generated_value,
                    curated_doc,
                    curated_value,
                    &format!("{context}[{index}]"),
                );
            }
        }
        _ => assert_eq!(generated, curated, "value drift for {context}"),
    }
}

fn assert_required_flag(generated: Option<&Value>, curated: Option<&Value>, context: &str) {
    let generated = generated.and_then(Value::as_bool).unwrap_or(false);
    let curated = curated.and_then(Value::as_bool).unwrap_or(false);
    assert!(generated || !curated, "required-flag drift for {context}");
}

fn assert_required_items(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_superset(&curated),
        "required items drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_enum_subset(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    let curated = curated
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<BTreeSet<_>>();
    assert!(
        generated.is_subset(&curated),
        "enum drift for {context}: generated={generated:?}, curated={curated:?}"
    );
}

fn assert_numeric_at_least(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated >= curated, "numeric drift for {context}");
}

fn assert_numeric_at_most(generated: &Value, curated: &Value, context: &str) {
    let generated = generated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric generated value for {context}"));
    let curated = curated
        .as_f64()
        .unwrap_or_else(|| panic!("non-numeric curated value for {context}"));
    assert!(generated <= curated, "numeric drift for {context}");
}

fn parameter_key(docs: &SpecDocs<'_>, current_doc: DocName, parameter: &Value) -> String {
    let (_, parameter) = resolve_ref(docs, current_doc, parameter);
    format!(
        "{}:{}",
        parameter["in"].as_str().unwrap(),
        parameter["name"].as_str().unwrap()
    )
}

fn effective_operation(doc: &Value, path: &str, method: &str) -> Value {
    let mut operation = op(doc, path, method).clone();
    let mut parameters = Vec::new();

    if let Some(path_parameters) = doc["paths"][path]["parameters"].as_array() {
        parameters.extend(path_parameters.iter().cloned());
    }
    if let Some(operation_parameters) = operation["parameters"].as_array() {
        parameters.extend(operation_parameters.iter().cloned());
    }
    if !parameters.is_empty() {
        operation["parameters"] = Value::Array(parameters);
    }

    operation
}

fn resolve_ref<'a>(
    docs: &'a SpecDocs<'a>,
    mut current_doc: DocName,
    mut value: &'a Value,
) -> (DocName, &'a Value) {
    while let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let (next_doc, pointer) = parse_ref(current_doc, reference);
        current_doc = next_doc;
        value = doc(docs, current_doc)
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("missing ref target `{reference}`"));
    }

    (current_doc, value)
}

fn parse_ref(current_doc: DocName, reference: &str) -> (DocName, String) {
    let (doc_name, pointer) = reference.split_once('#').unwrap_or((reference, ""));
    let doc = match doc_name {
        "" => current_doc,
        "./common.yaml" => DocName::Common,
        "./system.yaml" => DocName::System,
        "./sessions.yaml" => DocName::Sessions,
        "./targets.yaml" => DocName::Targets,
        "./alerts.yaml" => DocName::Alerts,
        "./schedules.yaml" => DocName::Schedules,
        "./credentials.yaml" => DocName::Credentials,
        "./port-lists.yaml" => DocName::PortLists,
        "./feeds.yaml" => DocName::Feeds,
        "./identity.yaml" => DocName::Identity,
        "./tasks.yaml" => DocName::Tasks,
        "./reports.yaml" => DocName::Reports,
        "./results.yaml" => DocName::Results,
        "./scan-configs.yaml" => DocName::ScanConfigs,
        "./scanners.yaml" => DocName::Scanners,
        other => panic!("unsupported ref document `{other}`"),
    };

    let pointer = if pointer.is_empty() {
        String::new()
    } else {
        pointer.replace("~1", "/").replace("~0", "~")
    };

    (doc, pointer)
}

fn doc<'a>(docs: &'a SpecDocs<'a>, name: DocName) -> &'a Value {
    match name {
        DocName::Generated => docs.generated,
        DocName::System => docs.system,
        DocName::Sessions => docs.sessions,
        DocName::Targets => docs.targets,
        DocName::Alerts => docs.alerts,
        DocName::Schedules => docs.schedules,
        DocName::Credentials => docs.credentials,
        DocName::PortLists => docs.port_lists,
        DocName::Feeds => docs.feeds,
        DocName::SupportingResources => docs.supporting_resources,
        DocName::Identity => docs.identity,
        DocName::Tasks => docs.tasks,
        DocName::Reports => docs.reports,
        DocName::Results => docs.results,
        DocName::ScanConfigs => docs.scan_configs,
        DocName::Scanners => docs.scanners,
        DocName::Common => docs.common,
    }
}

fn op<'a>(doc: &'a Value, path: &str, method: &str) -> &'a Value {
    &doc["paths"][path][method]
}

fn path_names(doc: &Value) -> BTreeSet<&str> {
    doc["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}
