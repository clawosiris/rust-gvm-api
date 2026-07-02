from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from urllib import parse

from utils import Config, IntegrationError, HttpJsonClient, format_rfc3339, parse_datetime, parse_pagination, require_text


PER_PAGE = 1000
SEVERITY_THRESHOLD = 4.0


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
            raise IntegrationError("GVM create session response did not contain sessionToken.")
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
                raise IntegrationError(f"{context} page {page} did not return a data array.")
            for index, item in enumerate(data):
                if not isinstance(item, dict):
                    raise IntegrationError(
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
            raise IntegrationError("GVM session has not been created.")
        return {"Authorization": f"Bearer {self.session_token}"}

    def url(self, path: str, params: dict[str, str] | None = None) -> str:
        url = f"{self.config.gvm_gateway_base_url}/api/v1/{path.lstrip('/')}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        return url


def result_severity(result: dict[str, Any]) -> float:
    severity = result.get("severity")
    if severity is None:
        return 0.0
    try:
        return float(severity)
    except (TypeError, ValueError):
        raise IntegrationError(f"Result {result.get('id')} has non-numeric severity {severity!r}.")
