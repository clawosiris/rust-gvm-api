from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import parse

import requests


class IntegrationError(Exception):
    """Fatal example error that should be printed for the user."""


@dataclass(frozen=True)
class Config:
    gvm_gateway_base_url: str
    gvm_username: str
    gvm_password: str
    jira_site_url: str
    jira_email: str
    jira_api_token: str
    jira_project_key: str
    jira_issue_type: str
    jira_finding_key_field: str
    jira_labels: tuple[str, ...]
    jira_priority: str | None
    jira_closed_status_names: tuple[str, ...]
    jira_closed_status_categories: tuple[str, ...]
    jira_reopen_transition_name: str
    jira_lookback_hours: int
    jira_min_severity: float

    @classmethod
    def load(cls, env_path: Path) -> Config:
        values = DEFAULT_CONFIG_VALUES | read_env_file(env_path)
        values.update({key: value for key, value in os.environ.items() if key in CONFIG_KEYS})

        missing = [key for key in REQUIRED_CONFIG_KEYS if not values.get(key, "").strip()]
        if missing:
            joined = ", ".join(missing)
            raise IntegrationError(f"Missing required configuration value(s): {joined}. Check {env_path}.")

        gvm_gateway_base_url = values["GVM_GATEWAY_BASE_URL"].rstrip("/")
        if gvm_gateway_base_url.endswith("/api/v1"):
            raise IntegrationError("GVM_GATEWAY_BASE_URL must not include /api/v1; use the gateway root URL.")
        validate_http_url(gvm_gateway_base_url, "GVM_GATEWAY_BASE_URL")

        jira_site_url = values["JIRA_SITE_URL"].rstrip("/")
        if jira_site_url.endswith("/rest/api/3"):
            raise IntegrationError("JIRA_SITE_URL must not include /rest/api/3; use the Jira Cloud site URL.")
        validate_http_url(jira_site_url, "JIRA_SITE_URL")

        lookback_hours = parse_positive_int(values["JIRA_LOOKBACK_HOURS"], "JIRA_LOOKBACK_HOURS")
        min_severity = parse_float(values["JIRA_MIN_SEVERITY"], "JIRA_MIN_SEVERITY")

        return cls(
            gvm_gateway_base_url=gvm_gateway_base_url,
            gvm_username=values["GVM_GATEWAY_USERNAME"],
            gvm_password=values["GVM_GATEWAY_PASSWORD"],
            jira_site_url=jira_site_url,
            jira_email=values["JIRA_EMAIL"],
            jira_api_token=values["JIRA_API_TOKEN"],
            jira_project_key=values["JIRA_PROJECT_KEY"],
            jira_issue_type=values["JIRA_ISSUE_TYPE"],
            jira_finding_key_field=values["JIRA_FINDING_KEY_FIELD"],
            jira_labels=parse_csv(values["JIRA_LABELS"]),
            jira_priority=optional_config_value(values, "JIRA_PRIORITY"),
            jira_closed_status_names=parse_csv(values["JIRA_CLOSED_STATUS_NAMES"]),
            jira_closed_status_categories=parse_csv(values["JIRA_CLOSED_STATUS_CATEGORIES"]),
            jira_reopen_transition_name=values["JIRA_REOPEN_TRANSITION_NAME"],
            jira_lookback_hours=lookback_hours,
            jira_min_severity=min_severity,
        )


DEFAULT_CONFIG_VALUES = {
    "JIRA_ISSUE_TYPE": "Task",
    "JIRA_FINDING_KEY_FIELD": "GreenboneFindingKey",
    "JIRA_LABELS": "greenbone,gvm",
    "JIRA_PRIORITY": "",
    "JIRA_CLOSED_STATUS_NAMES": "",
    "JIRA_CLOSED_STATUS_CATEGORIES": "Done",
    "JIRA_LOOKBACK_HOURS": "24",
    "JIRA_MIN_SEVERITY": "4.0",
}


REQUIRED_CONFIG_KEYS = (
    "GVM_GATEWAY_BASE_URL",
    "GVM_GATEWAY_USERNAME",
    "GVM_GATEWAY_PASSWORD",
    "JIRA_SITE_URL",
    "JIRA_EMAIL",
    "JIRA_API_TOKEN",
    "JIRA_PROJECT_KEY",
    "JIRA_REOPEN_TRANSITION_NAME",
)


CONFIG_KEYS = REQUIRED_CONFIG_KEYS + tuple(DEFAULT_CONFIG_VALUES)


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise IntegrationError(f"Configuration file {path} does not exist. Copy .env.example to .env first.")

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise IntegrationError(f"Invalid .env line {line_number}: expected KEY=VALUE.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise IntegrationError(f"Invalid .env line {line_number}: key is empty.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def optional_config_value(values: dict[str, str], key: str) -> str | None:
    value = values.get(key, "").strip()
    return value or None


def parse_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def parse_positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise IntegrationError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise IntegrationError(f"{name} must be greater than zero.")
    return parsed


def parse_float(value: str, name: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise IntegrationError(f"{name} must be a number.") from exc


def format_http_failure(context: str, url: str, status: int, detail: str) -> str:
    body = detail.strip()
    message = f"{context} failed with HTTP {status} at {url}."
    if body:
        return f"{message} Response body: {body}"
    return f"{message} The server returned an empty response body."


def validate_http_url(url: str, name: str) -> None:
    parsed = parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise IntegrationError(f"{name} must be an HTTP or HTTPS URL.")


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

        validate_http_url(url, "request URL")

        body: str | None = None
        if payload is not None:
            body = json.dumps(payload)
            request_headers["Content-Type"] = "application/json"

        if basic_auth is not None:
            credentials = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
            token = base64.b64encode(credentials).decode("ascii")
            request_headers["Authorization"] = f"Basic {token}"

        try:
            response = requests.request(method, url, data=body, headers=request_headers, timeout=self.timeout)
        except requests.Timeout as exc:
            raise IntegrationError(
                f"{context} timed out after {self.timeout} seconds while waiting for {url}. "
                "Check that the configured service is running and reachable."
            ) from exc
        except requests.RequestException as exc:
            raise IntegrationError(f"{context} failed: {exc}") from exc

        if response.status_code not in expected_statuses:
            detail = response.text
            response_url = response.url or url
            raise IntegrationError(format_http_failure(context, response_url, response.status_code, detail))
        if response.status_code == 204 or not response.content:
            return {}
        try:
            parsed = response.json()
        except ValueError as exc:
            raise IntegrationError(f"{context} returned invalid JSON.") from exc
        if not isinstance(parsed, dict):
            raise IntegrationError(f"{context} returned JSON that is not an object.")
        return parsed


def parse_pagination(value: Any, context: str, page: int) -> dict[str, int]:
    if not isinstance(value, dict):
        raise IntegrationError(f"{context} page {page} did not return a pagination object.")
    parsed: dict[str, int] = {}
    for key in ("page", "perPage", "total", "totalPages"):
        if key not in value:
            raise IntegrationError(f"{context} page {page} pagination is missing required field {key}.")
        parsed[key] = require_int(value[key], f"{context} page {page} pagination.{key}")
    return parsed


def require_int(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise IntegrationError(f"{context} must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise IntegrationError(f"{context} must be an integer.") from exc


def require_text(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if value is None or str(value) == "":
        raise IntegrationError(f"{context} is missing required field {key}.")
    return str(value)


def parse_datetime(value: str, context: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    timezone_suffix = normalized[-5:]
    if len(timezone_suffix) == 5 and timezone_suffix[0] in {"+", "-"} and timezone_suffix[1:].isdigit():
        normalized = f"{normalized[:-5]}{timezone_suffix[:3]}:{timezone_suffix[3:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise IntegrationError(f"Invalid {context} timestamp {value!r}.") from exc
    if parsed.tzinfo is None:
        raise IntegrationError(f"Invalid {context} timestamp {value!r}: timezone is required.")
    return parsed.astimezone(timezone.utc)


def format_rfc3339(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc_value.isoformat().replace("+00:00", "Z")
