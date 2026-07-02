from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


PER_PAGE = 1000
SEVERITY_THRESHOLD = 4.0


class ExampleError(Exception):
    """Fatal example error that should be printed for the user."""


@dataclass(frozen=True)
class Config:
    gvm_gateway_base_url: str
    gvm_username: str
    gvm_password: str
    otobo_base_url: str
    otobo_web_service: str
    otobo_username: str
    otobo_password: str
    op_ticket_search: str
    op_ticket_get: str
    op_ticket_create: str
    op_ticket_update: str
    op_config_item_search: str
    op_config_item_upsert: str
    finding_key_field: str
    ticket_queue: str
    ticket_customer_user: str
    ticket_state_new: str
    ticket_priority: str
    ticket_article_sender_type: str
    ticket_article_type: str
    closed_states: tuple[str, ...]
    reopen_state: str
    config_item_class: str
    config_item_deployment_state: str
    config_item_incident_state: str
    attr_external_key: str
    attr_name: str
    attr_ip: str | None
    attr_hostname: str
    attr_os: str

    @classmethod
    def load(cls, env_path: Path) -> Config:
        values = read_env_file(env_path)
        values.update({key: value for key, value in os.environ.items() if key in REQUIRED_CONFIG_KEYS})

        missing = [key for key in REQUIRED_CONFIG_KEYS if not values.get(key, "").strip()]
        if missing:
            joined = ", ".join(missing)
            raise ExampleError(f"Missing required configuration value(s): {joined}. Check {env_path}.")

        gvm_gateway_base_url = values["GVM_GATEWAY_BASE_URL"].rstrip("/")
        if gvm_gateway_base_url.endswith("/api/v1"):
            raise ExampleError("GVM_GATEWAY_BASE_URL must not include /api/v1; use the gateway root URL.")

        closed_states = tuple(
            state.strip() for state in values["OTOBO_CLOSED_STATES"].split(",") if state.strip()
        )
        if not closed_states:
            raise ExampleError("OTOBO_CLOSED_STATES must contain at least one closed ticket state.")

        return cls(
            gvm_gateway_base_url=gvm_gateway_base_url,
            gvm_username=values["GVM_GATEWAY_USERNAME"],
            gvm_password=values["GVM_GATEWAY_PASSWORD"],
            otobo_base_url=values["OTOBO_BASE_URL"].rstrip("/"),
            otobo_web_service=values["OTOBO_WEB_SERVICE"].strip("/"),
            otobo_username=values["OTOBO_USERNAME"],
            otobo_password=values["OTOBO_PASSWORD"],
            op_ticket_search=values["OTOBO_OPERATION_TICKET_SEARCH"].strip("/"),
            op_ticket_get=values["OTOBO_OPERATION_TICKET_GET"].strip("/"),
            op_ticket_create=values["OTOBO_OPERATION_TICKET_CREATE"].strip("/"),
            op_ticket_update=values["OTOBO_OPERATION_TICKET_UPDATE"].strip("/"),
            op_config_item_search=values["OTOBO_OPERATION_CONFIG_ITEM_SEARCH"].strip("/"),
            op_config_item_upsert=values["OTOBO_OPERATION_CONFIG_ITEM_UPSERT"].strip("/"),
            finding_key_field=values["OTOBO_FINDING_KEY_FIELD"],
            ticket_queue=values["OTOBO_TICKET_QUEUE"],
            ticket_customer_user=values["OTOBO_TICKET_CUSTOMER_USER"],
            ticket_state_new=values["OTOBO_TICKET_STATE_NEW"],
            ticket_priority=values["OTOBO_TICKET_PRIORITY"],
            ticket_article_sender_type=values["OTOBO_TICKET_ARTICLE_SENDER_TYPE"],
            ticket_article_type=values["OTOBO_TICKET_ARTICLE_TYPE"],
            closed_states=closed_states,
            reopen_state=values["OTOBO_REOPEN_STATE"],
            config_item_class=values["OTOBO_CONFIG_ITEM_CLASS"],
            config_item_deployment_state=values["OTOBO_CONFIG_ITEM_DEPLOYMENT_STATE"],
            config_item_incident_state=values["OTOBO_CONFIG_ITEM_INCIDENT_STATE"],
            attr_external_key=values["OTOBO_CONFIG_ITEM_EXTERNAL_KEY_ATTRIBUTE"],
            attr_name=values["OTOBO_CONFIG_ITEM_NAME_ATTRIBUTE"],
            attr_ip=optional_config_value(values, "OTOBO_CONFIG_ITEM_IP_ATTRIBUTE"),
            attr_hostname=values["OTOBO_CONFIG_ITEM_HOSTNAME_ATTRIBUTE"],
            attr_os=values["OTOBO_CONFIG_ITEM_OS_ATTRIBUTE"],
        )


REQUIRED_CONFIG_KEYS = (
    "GVM_GATEWAY_BASE_URL",
    "GVM_GATEWAY_USERNAME",
    "GVM_GATEWAY_PASSWORD",
    "OTOBO_BASE_URL",
    "OTOBO_WEB_SERVICE",
    "OTOBO_USERNAME",
    "OTOBO_PASSWORD",
    "OTOBO_OPERATION_TICKET_SEARCH",
    "OTOBO_OPERATION_TICKET_GET",
    "OTOBO_OPERATION_TICKET_CREATE",
    "OTOBO_OPERATION_TICKET_UPDATE",
    "OTOBO_OPERATION_CONFIG_ITEM_SEARCH",
    "OTOBO_OPERATION_CONFIG_ITEM_UPSERT",
    "OTOBO_FINDING_KEY_FIELD",
    "OTOBO_TICKET_QUEUE",
    "OTOBO_TICKET_CUSTOMER_USER",
    "OTOBO_TICKET_STATE_NEW",
    "OTOBO_TICKET_PRIORITY",
    "OTOBO_TICKET_ARTICLE_SENDER_TYPE",
    "OTOBO_TICKET_ARTICLE_TYPE",
    "OTOBO_CLOSED_STATES",
    "OTOBO_REOPEN_STATE",
    "OTOBO_CONFIG_ITEM_CLASS",
    "OTOBO_CONFIG_ITEM_DEPLOYMENT_STATE",
    "OTOBO_CONFIG_ITEM_INCIDENT_STATE",
    "OTOBO_CONFIG_ITEM_EXTERNAL_KEY_ATTRIBUTE",
    "OTOBO_CONFIG_ITEM_NAME_ATTRIBUTE",
    "OTOBO_CONFIG_ITEM_HOSTNAME_ATTRIBUTE",
    "OTOBO_CONFIG_ITEM_OS_ATTRIBUTE",
)


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise ExampleError(f"Configuration file {path} does not exist. Copy .env.example to .env first.")

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ExampleError(f"Invalid .env line {line_number}: expected KEY=VALUE.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ExampleError(f"Invalid .env line {line_number}: key is empty.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def optional_config_value(values: dict[str, str], key: str) -> str | None:
    value = values.get(key, "").strip()
    return value or None


def format_http_failure(context: str, url: str, status: int, detail: str) -> str:
    body = detail.strip()
    message = f"{context} failed with HTTP {status} at {url}."
    if body:
        message = f"{message} Response body: {body}"
    else:
        message = f"{message} The server returned an empty response body."
    if context.startswith("OTOBO "):
        message = (
            f"{message} Check the OTOBO Generic Interface web service route, "
            "operation mapping, credentials, and OTOBO server logs for the backend error."
        )
    return message


class HttpJsonClient:
    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def request_json(
        self,
        method: str,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        basic_auth: tuple[str, str] | None = None,
        expected_statuses: tuple[int, ...] = (200,),
        context: str,
    ) -> dict[str, Any]:
        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        body: bytes | None = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        if basic_auth is not None:
            credentials = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
            token = base64.b64encode(credentials).decode("ascii")
            request_headers["Authorization"] = f"Basic {token}"

        req = request.Request(url=url, data=body, headers=request_headers, method=method)
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                response_body = response.read()
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ExampleError(format_http_failure(context, exc.url, exc.code, detail)) from exc
        except TimeoutError as exc:
            raise ExampleError(
                f"{context} timed out after {self.timeout} seconds while waiting for {url}. "
                "Check that the configured service is running and can reach its backend."
            ) from exc
        except error.URLError as exc:
            raise ExampleError(f"{context} failed: {exc.reason}") from exc

        if status not in expected_statuses:
            detail = response_body.decode("utf-8", errors="replace")
            raise ExampleError(format_http_failure(context, url, status, detail))
        if status == 204 or not response_body:
            return {}
        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ExampleError(f"{context} returned invalid JSON.") from exc
        if not isinstance(parsed, dict):
            raise ExampleError(f"{context} returned JSON that is not an object.")
        return parsed


class GvmClient:
    def __init__(self, config: Config, http: HttpJsonClient) -> None:
        self.config = config
        self.http = http
        self.session_token: str | None = None

    def create_session(self) -> None:
        response = self.http.request_json(
            "POST",
            self.url("session"),
            basic_auth=(self.config.gvm_username, self.config.gvm_password),
            expected_statuses=(201,),
            context="GVM create session POST /api/v1/session",
        )
        token = response.get("sessionToken")
        if not isinstance(token, str) or not token:
            raise ExampleError("GVM create session response did not contain sessionToken.")
        self.session_token = token

    def close_session(self) -> None:
        if self.session_token is None:
            return
        self.http.request_json(
            "DELETE",
            self.url("session"),
            headers=self.auth_headers(),
            expected_statuses=(204,),
            context="GVM close session DELETE /api/v1/session",
        )
        self.session_token = None

    def get_hosts(self) -> list[dict[str, Any]]:
        return self.get_paginated("hosts", "GVM GET /api/v1/hosts")

    def get_recent_reports(self, now_utc: datetime) -> list[dict[str, Any]]:
        cutoff = now_utc - timedelta(hours=24)
        cutoff_text = format_rfc3339(cutoff)
        reports = self.get_paginated(
            "reports",
            "GVM GET /api/v1/reports",
            {"filter": f"scan_start>{cutoff_text}"},
        )
        selected = []
        for report in reports:
            report_id = require_text(report, "id", "GVM report")
            scan_start_value = require_text(report, "scanStart", f"GVM report {report_id}")
            scan_start = parse_datetime(str(scan_start_value), "report scanStart")
            if scan_start >= cutoff:
                selected.append(report)
        return selected

    def get_report_results(self, report_id: str) -> list[dict[str, Any]]:
        results = self.get_paginated(
            f"reports/{parse.quote(report_id, safe='')}/results",
            f"GVM GET /api/v1/reports/{report_id}/results",
        )
        return [result for result in results if result_severity(result) > SEVERITY_THRESHOLD]

    def get_paginated(
        self,
        path: str,
        context: str,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        page = 1
        while True:
            page_params = dict(params or {})
            page_params["page"] = str(page)
            page_params["perPage"] = str(PER_PAGE)
            response = self.http.request_json(
                "GET",
                self.url(path, page_params),
                headers=self.auth_headers(),
                context=f"{context} page {page}",
            )
            data = response.get("data")
            if not isinstance(data, list):
                raise ExampleError(f"{context} page {page} did not return a data array.")
            for index, item in enumerate(data):
                if not isinstance(item, dict):
                    raise ExampleError(
                        f"{context} page {page} returned malformed data item at index {index}: "
                        "expected an object."
                    )
                collected.append(item)

            pagination = response.get("pagination")
            page_info = parse_pagination(pagination, context, page)
            total_pages = page_info["totalPages"]
            if page >= total_pages:
                break
            page += 1
        return collected

    def auth_headers(self) -> dict[str, str]:
        if self.session_token is None:
            raise ExampleError("GVM session has not been created.")
        return {"Authorization": f"Bearer {self.session_token}"}

    def url(self, path: str, params: dict[str, str] | None = None) -> str:
        url = f"{self.config.gvm_gateway_base_url}/api/v1/{path.lstrip('/')}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        return url


class OtoboClient:
    def __init__(self, config: Config, http: HttpJsonClient) -> None:
        self.config = config
        self.http = http

    def preflight(self) -> None:
        self.ticket_search_by_finding_key("__greenbone_preflight_no_match__")
        self.config_item_search("__greenbone_preflight_no_match__")

    def ticket_search_by_finding_key(self, finding_key: str) -> list[str]:
        payload = {
            dynamic_field_search_key(self.config.finding_key_field): {"Equals": finding_key},
        }
        response = self.call(self.config.op_ticket_search, payload, "OTOBO TicketSearch")
        return extract_search_id_list(
            response,
            ("TicketID", "TicketIDs", "Ticket"),
            "OTOBO TicketSearch",
        )

    def ticket_get(self, ticket_id: str) -> dict[str, Any]:
        payload = {"TicketID": ticket_id, "DynamicFields": 1, "AllArticles": 0}
        response = self.call(self.config.op_ticket_get, payload, f"OTOBO TicketGet {ticket_id}")
        validate_recognized_response(response, ("Ticket", "TicketID", "State"), f"OTOBO TicketGet {ticket_id}")
        return response

    def ticket_create(self, finding: Finding, config_item_id: str | None) -> str:
        payload = {
            "Ticket": {
                "Queue": self.config.ticket_queue,
                "CustomerUser": self.config.ticket_customer_user,
                "State": self.config.ticket_state_new,
                "Priority": self.config.ticket_priority,
                "Title": ticket_title(finding),
            },
            "Article": self.article_payload(finding),
            "DynamicField": [
                {"Name": self.config.finding_key_field, "Value": finding.key},
            ],
        }
        if config_item_id is not None:
            payload["Link"] = [config_item_link(config_item_id)]
        response = self.call(self.config.op_ticket_create, payload, "OTOBO TicketCreate")
        ticket_ids = extract_required_id_list(response, ("TicketID", "TicketNumber"), "OTOBO TicketCreate")
        if not ticket_ids:
            raise ExampleError("OTOBO TicketCreate response did not contain a ticket identifier.")
        return ticket_ids[0]

    def ticket_update(self, ticket_id: str, finding: Finding, reopen: bool, config_item_id: str | None) -> None:
        payload: dict[str, Any] = {
            "TicketID": ticket_id,
            "Article": self.article_payload(finding),
            "DynamicField": [
                {"Name": self.config.finding_key_field, "Value": finding.key},
            ],
        }
        if reopen:
            payload["Ticket"] = {"State": self.config.reopen_state}
        if config_item_id is not None:
            payload["Link"] = [config_item_link(config_item_id)]
        response = self.call(self.config.op_ticket_update, payload, f"OTOBO TicketUpdate {ticket_id}")
        validate_recognized_response(
            response,
            ("TicketID", "TicketNumber", "Ticket"),
            f"OTOBO TicketUpdate {ticket_id}",
        )

    def config_item_search(self, external_key: str) -> list[str]:
        payload = {
            "Class": self.config.config_item_class,
            config_item_dynamic_field_key(self.config.attr_external_key): {"Equals": external_key},
        }
        response = self.call(
            self.config.op_config_item_search,
            payload,
            "OTOBO ConfigItemSearch",
        )
        return extract_search_id_list(
            response,
            ("ConfigItemID", "ConfigItemIDs", "ConfigItem"),
            "OTOBO ConfigItemSearch",
        )

    def config_item_upsert(self, host: dict[str, Any], config_item_id: str | None = None) -> str:
        payload = self.config_item_payload(host)
        if config_item_id is not None:
            payload["ConfigItem"]["ConfigItemID"] = config_item_id
        response = self.call(
            self.config.op_config_item_upsert,
            payload,
            f"OTOBO ConfigItemUpsert host {host.get('id')}",
        )
        config_item_ids = extract_required_id_list(
            response,
            ("ConfigItemID", "ConfigItemNumber", "ConfigItem"),
            f"OTOBO ConfigItemUpsert host {host.get('id')}",
        )
        if not config_item_ids:
            raise ExampleError("OTOBO ConfigItemUpsert response did not contain a config item identifier.")
        return config_item_ids[0]

    def config_item_payload(self, host: dict[str, Any]) -> dict[str, Any]:
        host_id = require_text(host, "id", "GVM host")
        name = str(host.get("name") or host_id)
        config_item = {
            "Class": self.config.config_item_class,
            "DeploymentState": self.config.config_item_deployment_state,
            "IncidentState": self.config.config_item_incident_state,
            "Name": name,
        }
        add_config_item_dynamic_field(config_item, self.config.attr_external_key, host_id)
        add_config_item_dynamic_field(config_item, self.config.attr_name, host.get("name") or "")
        if self.config.attr_ip is not None:
            add_config_item_dynamic_field(config_item, self.config.attr_ip, host.get("ip") or "")
        add_config_item_dynamic_field(config_item, self.config.attr_hostname, host.get("hostname") or "")
        add_config_item_dynamic_field(config_item, self.config.attr_os, host.get("os") or "")
        return {
            "ConfigItem": config_item,
        }

    def article_payload(self, finding: Finding) -> dict[str, str]:
        return {
            "Subject": ticket_title(finding),
            "Body": format_article_body(finding),
            "ContentType": "text/plain; charset=utf-8",
            "SenderType": self.config.ticket_article_sender_type,
            "ArticleType": self.config.ticket_article_type,
        }

    def call(self, operation: str, payload: dict[str, Any], context: str) -> dict[str, Any]:
        request_payload = dict(payload)
        request_payload["UserLogin"] = self.config.otobo_username
        request_payload["Password"] = self.config.otobo_password
        response = self.http.request_json(
            "POST",
            self.operation_url(operation),
            payload=request_payload,
            context=context,
        )
        validate_otobo_response(response, context)
        return response

    def operation_url(self, operation: str) -> str:
        parts = [
            self.config.otobo_base_url,
            parse.quote(self.config.otobo_web_service.strip("/"), safe=""),
            quote_path(operation),
        ]
        return "/".join(part.strip("/") for part in parts if part.strip("/"))


@dataclass(frozen=True)
class SyncedConfigItem:
    id: str
    host: dict[str, Any]


@dataclass
class Finding:
    key: str
    nvt_oid: str
    host: str
    port: str
    latest_seen: datetime
    evidence: list[Evidence]


@dataclass(frozen=True)
class Evidence:
    report_id: str
    scan_start: datetime
    result: dict[str, Any]


def run(config: Config) -> None:
    http = HttpJsonClient()
    gvm = GvmClient(config, http)
    otobo = OtoboClient(config, http)

    otobo.preflight()
    gvm.create_session()

    sync_error: ExampleError | None = None
    try:
        hosts = gvm.get_hosts()
        synced_hosts = sync_cmdb_hosts(otobo, hosts)
        host_lookup = build_host_lookup(synced_hosts)

        reports = gvm.get_recent_reports(datetime.now(timezone.utc))
        report_results = []
        for report in reports:
            report_id = require_text(report, "id", "GVM report")
            for result in gvm.get_report_results(report_id):
                report_results.append((report, result))

        findings = aggregate_findings(report_results)
        unlinked_findings = sync_findings(otobo, config, findings, host_lookup)

        print(
            "Synchronization complete: "
            f"{len(hosts)} host(s), {len(reports)} report(s), {len(findings)} finding(s), "
            f"{unlinked_findings} without CMDB link."
        )
    except ExampleError as exc:
        sync_error = exc
        raise
    finally:
        try:
            gvm.close_session()
        except ExampleError as cleanup_error:
            if sync_error is None:
                raise
            print(f"Warning: {cleanup_error}", file=sys.stderr)


def sync_cmdb_hosts(otobo: OtoboClient, hosts: list[dict[str, Any]]) -> list[SyncedConfigItem]:
    synced = []
    for host in hosts:
        host_id = require_text(host, "id", "GVM host")
        config_item_ids = otobo.config_item_search(host_id)
        if len(config_item_ids) > 1:
            raise ExampleError(f"OTOBO returned multiple config items for GVM host id {host_id}.")
        existing_config_item_id = config_item_ids[0] if config_item_ids else None
        config_item_id = otobo.config_item_upsert(host, existing_config_item_id)
        synced.append(SyncedConfigItem(id=config_item_id, host=host))
    return synced


def build_host_lookup(synced_hosts: list[SyncedConfigItem]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for synced in synced_hosts:
        for field in ("ip", "name", "hostname"):
            value = synced.host.get(field)
            if not value:
                continue
            key = str(value)
            existing = lookup.get(key)
            if existing is not None and existing != synced.id:
                raise ExampleError(
                    f"Host lookup value {key!r} matches multiple OTOBO config items "
                    f"({existing} and {synced.id}). Make host inventory values unique."
                )
            lookup[key] = synced.id
    return lookup


def sync_findings(
    otobo: OtoboClient,
    config: Config,
    findings: list[Finding],
    host_lookup: dict[str, str],
) -> int:
    unlinked_findings = 0
    for finding in findings:
        config_item_id = host_lookup.get(finding.host)
        if config_item_id is None:
            unlinked_findings += 1
            print(
                "Warning: syncing finding "
                f"{finding.key!r} without a CMDB link because host {finding.host!r} "
                "is not present in synced GVM hosts yet. A later run will add the link "
                "when the host asset is available.",
                file=sys.stderr,
            )
        sync_ticket(otobo, config, finding, config_item_id)
    return unlinked_findings


def aggregate_findings(report_results: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for report, result in report_results:
        report_id = require_text(report, "id", "GVM report")
        scan_start = parse_datetime(require_text(report, "scanStart", f"GVM report {report_id}"), "report scanStart")
        nvt = result.get("nvt")
        if not isinstance(nvt, dict):
            raise ExampleError(f"Severity-eligible result {result.get('id')} is missing nvt data.")
        nvt_oid = require_text(nvt, "oid", f"severity-eligible result {result.get('id')} nvt")
        host = require_text(result, "host", f"severity-eligible result {result.get('id')}")
        port = require_text(result, "port", f"severity-eligible result {result.get('id')}")
        key = f"{nvt_oid}|{host}|{port}"
        evidence = Evidence(report_id=report_id, scan_start=scan_start, result=result)
        if key not in findings:
            findings[key] = Finding(
                key=key,
                nvt_oid=nvt_oid,
                host=host,
                port=port,
                latest_seen=scan_start,
                evidence=[evidence],
            )
            continue
        finding = findings[key]
        finding.evidence.append(evidence)
        if scan_start > finding.latest_seen:
            finding.latest_seen = scan_start
    return list(findings.values())


def sync_ticket(otobo: OtoboClient, config: Config, finding: Finding, config_item_id: str | None) -> None:
    ticket_ids = otobo.ticket_search_by_finding_key(finding.key)
    if len(ticket_ids) > 1:
        raise ExampleError(f"OTOBO returned multiple tickets for finding key {finding.key}.")
    if not ticket_ids:
        otobo.ticket_create(finding, config_item_id)
        return

    ticket_id = ticket_ids[0]
    ticket = otobo.ticket_get(ticket_id)
    state = require_ticket_state(ticket, ticket_id)
    reopen = state in config.closed_states
    otobo.ticket_update(ticket_id, finding, reopen, config_item_id)


def format_article_body(finding: Finding) -> str:
    first_result = finding.evidence[0].result
    nvt = first_result.get("nvt") if isinstance(first_result.get("nvt"), dict) else {}
    lines = [
        "Greenbone finding observed by GVM REST API.",
        "",
        f"Finding key: {finding.key}",
        f"Latest seen: {format_rfc3339(finding.latest_seen)}",
        f"NVT OID: {finding.nvt_oid}",
        f"NVT name: {nvt.get('name') or first_result.get('name') or 'n/a'}",
        f"Host: {finding.host}",
        f"Port: {finding.port}",
    ]

    lines.extend(["", "Evidence:"])
    for index, evidence in enumerate(finding.evidence, start=1):
        result = evidence.result
        result_nvt = result.get("nvt") if isinstance(result.get("nvt"), dict) else {}
        lines.extend(
            [
                f"- #{index}",
                f"  Report ID: {evidence.report_id}",
                f"  Result ID: {result.get('id') or 'n/a'}",
                f"  Scan start: {format_rfc3339(evidence.scan_start)}",
                f"  NVT OID: {result_nvt.get('oid') or finding.nvt_oid}",
                f"  NVT name: {result_nvt.get('name') or result.get('name') or 'n/a'}",
                f"  Host: {result.get('host') or finding.host}",
                f"  Port: {result.get('port') or finding.port}",
                f"  Severity: {result.get('severity', 'n/a')}",
            ]
        )
        if result.get("threat"):
            lines.append(f"  Threat: {result['threat']}")
        cves = result_nvt.get("cves")
        if isinstance(cves, list) and cves:
            lines.append(f"  CVEs: {', '.join(str(cve) for cve in cves)}")
        description = result.get("description")
        if description:
            lines.extend(["  Description:", indent_text(str(description), "    ")])
    return "\n".join(lines)


def ticket_title(finding: Finding) -> str:
    first_result = finding.evidence[0].result
    name = first_result.get("name")
    if not name and isinstance(first_result.get("nvt"), dict):
        name = first_result["nvt"].get("name")
    return f"Greenbone finding: {name or finding.nvt_oid} on {finding.host}"


def config_item_link(config_item_id: str) -> dict[str, str]:
    return {
        "TargetObject": "ITSMConfigItem",
        "TargetKey": config_item_id,
        "Type": "RelevantTo",
        "State": "Valid",
    }


def extract_ticket_state(response: dict[str, Any]) -> str | None:
    candidates: list[Any] = [response]
    ticket = response.get("Ticket")
    if isinstance(ticket, dict):
        candidates.append(ticket)
    elif isinstance(ticket, list):
        candidates.extend(item for item in ticket if isinstance(item, dict))
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("State") is not None:
            return str(candidate["State"])
    return None


def require_ticket_state(response: dict[str, Any], ticket_id: str) -> str:
    state = extract_ticket_state(response)
    if state is None:
        raise ExampleError(
            f"OTOBO TicketGet {ticket_id} response did not expose a ticket state. "
            "Check that the TicketGet Generic Interface operation returns the State field."
        )
    return state


def extract_id_list(response: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    for key in keys:
        if key not in response:
            continue
        value = response[key]
        if isinstance(value, list):
            ids = []
            for item in value:
                if isinstance(item, dict):
                    extracted = first_present(item, ("TicketID", "TicketNumber", "ConfigItemID", "ConfigItemNumber", "ID"))
                    if extracted is not None:
                        ids.append(str(extracted))
                elif item is not None:
                    ids.append(str(item))
            return ids
        if isinstance(value, dict):
            extracted = first_present(value, ("TicketID", "TicketNumber", "ConfigItemID", "ConfigItemNumber", "ID"))
            return [str(extracted)] if extracted is not None else []
        if value is not None:
            return [str(value)]
    return []


def extract_required_id_list(response: dict[str, Any], keys: tuple[str, ...], context: str) -> list[str]:
    if not any(key in response for key in keys):
        expected = ", ".join(keys)
        raise ExampleError(
            f"{context} response is missing expected response field(s): {expected}. "
            "Check the OTOBO Generic Interface operation mapping and permissions."
        )
    return extract_id_list(response, keys)


def extract_search_id_list(response: dict[str, Any], keys: tuple[str, ...], context: str) -> list[str]:
    if not response:
        return []
    return extract_required_id_list(response, keys, context)


def validate_otobo_response(response: dict[str, Any], context: str) -> None:
    if "Success" in response and not is_success_marker(response["Success"]):
        raise ExampleError(f"{context} was rejected by OTOBO: Success={response['Success']!r}.")

    error_value = first_present(response, ("Error", "ErrorMessage", "ErrorCode", "Fault", "FaultString"))
    if error_value is not None:
        raise ExampleError(f"{context} was rejected by OTOBO: {format_otobo_error(error_value)}")


def validate_recognized_response(response: dict[str, Any], keys: tuple[str, ...], context: str) -> None:
    if "Success" in response and is_success_marker(response["Success"]):
        return
    if any(key in response for key in keys):
        return
    expected = ", ".join(keys)
    detail = json.dumps(response, sort_keys=True)
    raise ExampleError(
        f"{context} response is missing expected success field(s): {expected}. "
        f"Response: {detail}"
    )


def is_success_marker(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "success", "ok"}
    return False


def format_otobo_error(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("ErrorMessage", "Message", "FaultString", "ErrorCode"):
            if value.get(key):
                return str(value[key])
        return json.dumps(value, sort_keys=True)
    if isinstance(value, list):
        return json.dumps(value)
    return str(value)


def first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if data.get(key) is not None:
            return data[key]
    return None


def parse_pagination(value: Any, context: str, page: int) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ExampleError(f"{context} page {page} did not return a pagination object.")
    parsed: dict[str, int] = {}
    for key in ("page", "perPage", "total", "totalPages"):
        if key not in value:
            raise ExampleError(f"{context} page {page} pagination is missing required field {key}.")
        parsed[key] = require_int(value[key], f"{context} page {page} pagination.{key}")
    return parsed


def require_int(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise ExampleError(f"{context} must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ExampleError(f"{context} must be an integer.") from exc


def require_text(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if value is None or str(value) == "":
        raise ExampleError(f"{context} is missing required field {key}.")
    return str(value)


def result_severity(result: dict[str, Any]) -> float:
    severity = result.get("severity")
    if severity is None:
        return 0.0
    try:
        return float(severity)
    except (TypeError, ValueError):
        raise ExampleError(f"Result {result.get('id')} has non-numeric severity {severity!r}.")


def parse_datetime(value: str, context: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ExampleError(f"Invalid {context} timestamp {value!r}.") from exc
    if parsed.tzinfo is None:
        raise ExampleError(f"Invalid {context} timestamp {value!r}: timezone is required.")
    return parsed.astimezone(timezone.utc)


def format_rfc3339(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc_value.isoformat().replace("+00:00", "Z")


def dynamic_field_search_key(field_name: str) -> str:
    return f"DynamicField_{field_name}"


def config_item_dynamic_field_key(field_name: str) -> str:
    if field_name.startswith("DynamicField_"):
        return field_name
    return f"DynamicField_{field_name}"


def add_config_item_dynamic_field(config_item: dict[str, Any], field_name: str, value: Any) -> None:
    if field_name == "Name":
        return
    config_item[config_item_dynamic_field_key(field_name)] = value


def quote_path(path: str) -> str:
    return "/".join(parse.quote(part, safe="") for part in path.strip("/").split("/") if part)


def indent_text(value: str, prefix: str) -> str:
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())


def main() -> int:
    try:
        config = Config.load(Path(__file__).with_name(".env"))
        run(config)
    except ExampleError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
