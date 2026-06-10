mod common;

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use common::spawn_server;
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateTaskInput, GatewayError, ModifyTaskInput, Pagination, SessionManager, Task, TaskAction,
    TaskObservers, TaskPage, TaskPort, TaskQuery,
};
use gvm_gateway_gvmd::StaticGvmdAdapter;
use gvm_gateway_rest::{
    router::build_router,
    targets::{build_gmp_filter, CreateTargetRequest, ModifyTargetRequest, TargetListQuery},
};
use http::{Method, StatusCode};
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpListener;

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
        generated_route_methods(&json),
        expected_route_methods(),
        "generated OpenAPI route/method set drifted from the documented route inventory"
    );

    for route in route_contracts() {
        for method in route.methods {
            assert_operation_contract(
                &docs,
                route.spec_path,
                method,
                route.curated_doc,
                route.curated_path,
            );
        }
    }

    handle.abort();
}

#[tokio::test]
async fn documented_route_inventory_matches_live_router_dispatch() {
    let adapter = StaticGvmdAdapter::ready("22.7");
    let (addr, handle) = spawn_server(adapter.clone(), adapter).await;
    let client = Client::new();
    let session_token = create_route_probe_session(&client, addr).await;

    for route in route_contracts() {
        for method in route.methods {
            let response = build_route_probe_request(&client, addr, &route, method, &session_token)
                .send()
                .await
                .unwrap();

            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "router did not expose {} {}",
                method,
                route.runtime_path()
            );
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "router rejected documented method {} {}",
                method,
                route.runtime_path()
            );
        }
    }

    handle.abort();
}

#[tokio::test]
async fn update_task_preserves_preferences_through_handler() {
    let captured = Arc::new(Mutex::new(None));
    let task_port = Arc::new(CapturingTaskPort {
        captured: Arc::clone(&captured),
    });
    let (addr, token, handle) = spawn_task_server(task_port).await;

    // Regression coverage for issue #228: task preferences must survive the
    // full REST route path, not just direct request validation or gvmd emission.
    let response = Client::new()
        .put(format!(
            "http://{addr}/api/v1/tasks/550e8400-e29b-41d4-a716-446655440000"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "preferences": {
                "scanner.max_hosts": "64"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let input = captured
        .lock()
        .unwrap()
        .clone()
        .expect("modify_task input should be captured");
    assert_eq!(
        input.preferences,
        vec![("scanner.max_hosts".to_string(), "64".to_string())]
    );

    handle.abort();
}

async fn spawn_task_server(
    task_port: Arc<dyn TaskPort>,
) -> (std::net::SocketAddr, String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(SessionManager::default());
    let token = sessions.create("admin").unwrap().token;
    let adapter = Arc::new(StaticGvmdAdapter::ready("22.7"));
    let service = GatewayService::new(
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        task_port,
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter.clone(),
        adapter,
        sessions,
    );
    let app = build_router(service);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, token, handle)
}

struct CapturingTaskPort {
    captured: Arc<Mutex<Option<ModifyTaskInput>>>,
}

#[async_trait]
impl TaskPort for CapturingTaskPort {
    async fn list_tasks(&self, _: &str, query: &TaskQuery) -> Result<TaskPage, GatewayError> {
        Ok(TaskPage {
            data: vec![],
            pagination: Pagination {
                page: query.page,
                per_page: query.per_page,
                total: 0,
                total_pages: 0,
            },
        })
    }

    async fn create_task(&self, _: &str, _: CreateTaskInput) -> Result<String, GatewayError> {
        Err(GatewayError::Internal(
            "create_task is not used by this test port".to_string(),
        ))
    }

    async fn get_task(&self, _: &str, id: &str) -> Result<Task, GatewayError> {
        Ok(task_response(id, "Captured Task"))
    }

    async fn modify_task(
        &self,
        _: &str,
        id: &str,
        input: ModifyTaskInput,
    ) -> Result<Task, GatewayError> {
        *self.captured.lock().unwrap() = Some(input);
        Ok(task_response(id, "Captured Task"))
    }

    async fn delete_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "delete_task is not used by this test port".to_string(),
        ))
    }

    async fn start_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::Internal(
            "start_task is not used by this test port".to_string(),
        ))
    }

    async fn stop_task(&self, _: &str, _: &str) -> Result<(), GatewayError> {
        Err(GatewayError::Internal(
            "stop_task is not used by this test port".to_string(),
        ))
    }

    async fn resume_task(&self, _: &str, _: &str) -> Result<TaskAction, GatewayError> {
        Err(GatewayError::Internal(
            "resume_task is not used by this test port".to_string(),
        ))
    }
}

fn task_response(id: &str, name: &str) -> Task {
    Task {
        id: id.to_string(),
        name: name.to_string(),
        comment: None,
        status: "New".to_string(),
        progress: None,
        target: None,
        scan_config: None,
        scanner: None,
        schedule: None,
        alerts: vec![],
        alterable: None,
        hosts_ordering: None,
        observers: TaskObservers::default(),
        schedule_periods: None,
        last_report: None,
        current_report: None,
        report_count: None,
        in_use: false,
        writable: true,
    }
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
    // Modify-target credential IDs use the same UUID validation contract as
    // create-target credential IDs, preserving symmetry between both paths.
    assert!(ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: Some("still-not-a-uuid".to_string()),
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
        port_list_id: None,
        ssh_credential_id: Some("not-a-uuid".to_string()),
        smb_credential_id: None,
        esxi_credential_id: None,
        snmp_credential_id: None,
    }
    .validate()
    .is_err());
}

#[test]
fn modify_requests_map_mutable_fields() {
    let target_input = ModifyTargetRequest {
        name: None,
        comment: None,
        hosts: None,
        exclude_hosts: None,
        alive_test: None,
        port_list_id: None,
        ssh_credential_id: Some("550e8400-e29b-41d4-a716-446655440001".to_string()),
        smb_credential_id: Some("550e8400-e29b-41d4-a716-446655440002".to_string()),
        esxi_credential_id: Some("550e8400-e29b-41d4-a716-446655440003".to_string()),
        snmp_credential_id: Some("550e8400-e29b-41d4-a716-446655440004".to_string()),
    }
    .validate()
    .expect("valid credential IDs should map into modify-target input");
    assert_eq!(
        target_input.ssh_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440001")
    );
    assert_eq!(
        target_input.smb_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440002")
    );
    assert_eq!(
        target_input.esxi_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440003")
    );
    assert_eq!(
        target_input.snmp_credential_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440004")
    );

    let task_input =
        serde_json::from_value::<gvm_gateway_rest::tasks::ModifyTaskRequest>(serde_json::json!({
            "preferences": {
                "scanner.max_hosts": "64"
            }
        }))
        .expect("modify-task preferences should deserialize");
    let task_input = task_input
        .validate()
        .expect("preferences do not affect ID validation");

    assert_eq!(
        task_input.preferences,
        vec![("scanner.max_hosts".to_string(), "64".to_string())]
    );
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

struct RouteContract {
    spec_path: &'static str,
    methods: &'static [&'static str],
    curated_doc: DocName,
    curated_path: &'static str,
}

impl RouteContract {
    fn runtime_path(&self) -> String {
        let prefixed = match self.spec_path {
            "/health" | "/ready" => self.spec_path.to_string(),
            "/openapi.json" => "/api/v1/openapi.json".to_string(),
            _ => format!("/api/v1{}", self.spec_path),
        };

        prefixed.replace("{id}", "not-a-uuid")
    }
}

fn route_contracts() -> Vec<RouteContract> {
    vec![
        RouteContract { spec_path: "/health", methods: &["get"], curated_doc: DocName::System, curated_path: "/health" },
        RouteContract { spec_path: "/ready", methods: &["get"], curated_doc: DocName::System, curated_path: "/ready" },
        RouteContract { spec_path: "/version", methods: &["get"], curated_doc: DocName::System, curated_path: "/version" },
        RouteContract { spec_path: "/openapi.json", methods: &["get"], curated_doc: DocName::System, curated_path: "/openapi.json" },
        RouteContract { spec_path: "/session", methods: &["post", "get", "delete"], curated_doc: DocName::Sessions, curated_path: "/session" },
        RouteContract { spec_path: "/targets", methods: &["get", "post"], curated_doc: DocName::Targets, curated_path: "/targets" },
        RouteContract { spec_path: "/targets/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Targets, curated_path: "/targets/{id}" },
        RouteContract { spec_path: "/alerts", methods: &["get", "post"], curated_doc: DocName::Alerts, curated_path: "/alerts" },
        RouteContract { spec_path: "/alerts/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Alerts, curated_path: "/alerts/{id}" },
        RouteContract { spec_path: "/timezones", methods: &["get"], curated_doc: DocName::Schedules, curated_path: "/timezones" },
        RouteContract { spec_path: "/schedules", methods: &["get", "post"], curated_doc: DocName::Schedules, curated_path: "/schedules" },
        RouteContract { spec_path: "/schedules/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Schedules, curated_path: "/schedules/{id}" },
        RouteContract { spec_path: "/credential-stores", methods: &["get"], curated_doc: DocName::Credentials, curated_path: "/credential-stores" },
        RouteContract { spec_path: "/credentials", methods: &["get", "post"], curated_doc: DocName::Credentials, curated_path: "/credentials" },
        RouteContract { spec_path: "/credentials/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Credentials, curated_path: "/credentials/{id}" },
        RouteContract { spec_path: "/port-lists", methods: &["get", "post"], curated_doc: DocName::PortLists, curated_path: "/port-lists" },
        RouteContract { spec_path: "/port-lists/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::PortLists, curated_path: "/port-lists/{id}" },
        RouteContract { spec_path: "/feeds", methods: &["get"], curated_doc: DocName::Feeds, curated_path: "/feeds" },
        RouteContract { spec_path: "/feeds/sync", methods: &["post"], curated_doc: DocName::Feeds, curated_path: "/feeds/sync" },
        RouteContract { spec_path: "/hosts", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/hosts" },
        RouteContract { spec_path: "/hosts/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/hosts/{id}" },
        RouteContract { spec_path: "/report-formats", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/report-formats" },
        RouteContract { spec_path: "/report-formats/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/report-formats/{id}" },
        RouteContract { spec_path: "/filters", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/filters" },
        RouteContract { spec_path: "/filters/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/filters/{id}" },
        RouteContract { spec_path: "/tags", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/tags" },
        RouteContract { spec_path: "/tags/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/tags/{id}" },
        RouteContract { spec_path: "/tickets", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/tickets" },
        RouteContract { spec_path: "/tickets/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/tickets/{id}" },
        RouteContract { spec_path: "/notes", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/notes" },
        RouteContract { spec_path: "/notes/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/notes/{id}" },
        RouteContract { spec_path: "/overrides", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/overrides" },
        RouteContract { spec_path: "/overrides/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/overrides/{id}" },
        RouteContract { spec_path: "/nvts", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/nvts" },
        RouteContract { spec_path: "/nvts/{id}", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/nvts/{id}" },
        RouteContract { spec_path: "/nvt-families", methods: &["get"], curated_doc: DocName::SupportingResources, curated_path: "/nvt-families" },
        RouteContract { spec_path: "/users", methods: &["get", "post"], curated_doc: DocName::Identity, curated_path: "/users" },
        RouteContract { spec_path: "/users/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Identity, curated_path: "/users/{id}" },
        RouteContract { spec_path: "/groups", methods: &["get", "post"], curated_doc: DocName::Identity, curated_path: "/groups" },
        RouteContract { spec_path: "/groups/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Identity, curated_path: "/groups/{id}" },
        RouteContract { spec_path: "/roles", methods: &["get", "post"], curated_doc: DocName::Identity, curated_path: "/roles" },
        RouteContract { spec_path: "/roles/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Identity, curated_path: "/roles/{id}" },
        RouteContract { spec_path: "/permissions", methods: &["get", "post"], curated_doc: DocName::Identity, curated_path: "/permissions" },
        RouteContract { spec_path: "/permissions/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Identity, curated_path: "/permissions/{id}" },
        RouteContract { spec_path: "/user-settings", methods: &["get"], curated_doc: DocName::Identity, curated_path: "/user-settings" },
        RouteContract { spec_path: "/user-settings/{id}", methods: &["get", "put"], curated_doc: DocName::Identity, curated_path: "/user-settings/{id}" },
        RouteContract { spec_path: "/tasks", methods: &["get", "post"], curated_doc: DocName::Tasks, curated_path: "/tasks" },
        RouteContract { spec_path: "/tasks/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::Tasks, curated_path: "/tasks/{id}" },
        RouteContract { spec_path: "/tasks/{id}/start", methods: &["post"], curated_doc: DocName::Tasks, curated_path: "/tasks/{id}/start" },
        RouteContract { spec_path: "/tasks/{id}/stop", methods: &["post"], curated_doc: DocName::Tasks, curated_path: "/tasks/{id}/stop" },
        RouteContract { spec_path: "/tasks/{id}/resume", methods: &["post"], curated_doc: DocName::Tasks, curated_path: "/tasks/{id}/resume" },
        RouteContract { spec_path: "/reports", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports" },
        RouteContract { spec_path: "/reports/{id}", methods: &["get", "delete"], curated_doc: DocName::Reports, curated_path: "/reports/{id}" },
        RouteContract { spec_path: "/reports/{id}/export", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/export" },
        RouteContract { spec_path: "/reports/{id}/results", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/results" },
        RouteContract { spec_path: "/reports/{id}/vulnerabilities", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/vulnerabilities" },
        RouteContract { spec_path: "/reports/{id}/tls-certificates", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/tls-certificates" },
        RouteContract { spec_path: "/reports/{id}/errors", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/errors" },
        RouteContract { spec_path: "/reports/{id}/closed-cves", methods: &["get"], curated_doc: DocName::Reports, curated_path: "/reports/{id}/closed-cves" },
        RouteContract { spec_path: "/results", methods: &["get"], curated_doc: DocName::Results, curated_path: "/results" },
        RouteContract { spec_path: "/results/{id}", methods: &["get"], curated_doc: DocName::Results, curated_path: "/results/{id}" },
        RouteContract { spec_path: "/scan-configs", methods: &["get", "post"], curated_doc: DocName::ScanConfigs, curated_path: "/scan-configs" },
        RouteContract { spec_path: "/scan-configs/{id}", methods: &["get", "put", "delete"], curated_doc: DocName::ScanConfigs, curated_path: "/scan-configs/{id}" },
        RouteContract { spec_path: "/scanners", methods: &["get"], curated_doc: DocName::Scanners, curated_path: "/scanners" },
        RouteContract { spec_path: "/scanners/{id}", methods: &["get"], curated_doc: DocName::Scanners, curated_path: "/scanners/{id}" },
    ]
}

fn expected_route_methods() -> BTreeSet<(String, String)> {
    route_contracts()
        .into_iter()
        .flat_map(|route| {
            route.methods.iter().map(move |method| {
                (route.spec_path.to_string(), (*method).to_string())
            })
        })
        .collect()
}

fn generated_route_methods(doc: &Value) -> BTreeSet<(String, String)> {
    doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, methods)| {
            methods.as_object().unwrap().keys().map(move |method| {
                (path.clone(), method.clone())
            })
        })
        .collect()
}

fn build_route_probe_request(
    client: &Client,
    addr: std::net::SocketAddr,
    route: &RouteContract,
    method: &str,
    session_token: &str,
) -> reqwest::RequestBuilder {
    let runtime_path = route.runtime_path();
    let wire_method = method.to_ascii_uppercase();
    let request = client.request(
        Method::from_bytes(wire_method.as_bytes()).expect("documented methods must be valid"),
        format!("http://{addr}{runtime_path}"),
    );

    match runtime_path.as_str() {
        "/health" | "/ready" | "/api/v1/version" | "/api/v1/openapi.json" => request,
        "/api/v1/session" if method == "post" => {
            request.header("Authorization", "Basic YWRtaW46c2VjcmV0")
        }
        _ => request.bearer_auth(session_token),
    }
}

async fn create_route_probe_session(client: &Client, addr: std::net::SocketAddr) -> String {
    client
        .post(format!("http://{addr}/api/v1/session"))
        .header("Authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string()
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
