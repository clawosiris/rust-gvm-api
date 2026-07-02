from __future__ import annotations

import json
from typing import Any
from urllib import parse

from utils import Config, IntegrationError, HttpJsonClient, first_present, format_rfc3339, indent_text, quote_path, require_text


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

    def ticket_create(self, finding: Any, config_item_id: str | None) -> str:
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
            raise IntegrationError("OTOBO TicketCreate response did not contain a ticket identifier.")
        return ticket_ids[0]

    def ticket_update(self, ticket_id: str, finding: Any, reopen: bool, config_item_id: str | None) -> None:
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
            raise IntegrationError("OTOBO ConfigItemUpsert response did not contain a config item identifier.")
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

    def article_payload(self, finding: Any) -> dict[str, str]:
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
        raise IntegrationError(
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
        raise IntegrationError(
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
        raise IntegrationError(f"{context} was rejected by OTOBO: Success={response['Success']!r}.")

    error_value = first_present(response, ("Error", "ErrorMessage", "ErrorCode", "Fault", "FaultString"))
    if error_value is not None:
        raise IntegrationError(f"{context} was rejected by OTOBO: {format_otobo_error(error_value)}")


def validate_recognized_response(response: dict[str, Any], keys: tuple[str, ...], context: str) -> None:
    if "Success" in response and is_success_marker(response["Success"]):
        return
    if any(key in response for key in keys):
        return
    expected = ", ".join(keys)
    detail = json.dumps(response, sort_keys=True)
    raise IntegrationError(
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


def format_article_body(finding: Any) -> str:
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


def ticket_title(finding: Any) -> str:
    first_result = finding.evidence[0].result
    name = first_result.get("name")
    if not name and isinstance(first_result.get("nvt"), dict):
        name = first_result["nvt"].get("name")
    return f"Greenbone finding: {name or finding.nvt_oid} on {finding.host}"
