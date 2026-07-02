from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


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


def quote_path(path: str) -> str:
    return "/".join(parse.quote(part, safe="") for part in path.strip("/").split("/") if part)


def indent_text(value: str, prefix: str) -> str:
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())


def first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if data.get(key) is not None:
            return data[key]
    return None
