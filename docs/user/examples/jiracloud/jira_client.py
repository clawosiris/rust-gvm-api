from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from utils import Config, IntegrationError, parse_datetime


MAX_EVIDENCE_ROWS = 10


class JiraIssueClient:
    def __init__(self, config: Config, jira: Any) -> None:
        self.config = config
        self.jira = jira
        self.finding_key_field_id: str | None = None
        self.finding_key_field_name: str | None = None
        self.issue_type_id: str | None = None

    @classmethod
    def connect(cls, config: Config) -> JiraIssueClient:
        try:
            from jira import JIRA
        except ImportError as exc:
            raise IntegrationError("Missing Python dependency 'jira'. Run `uv sync` or `uv run python main.py`.") from exc
        jira = JIRA(server=config.jira_site_url, basic_auth=(config.jira_email, config.jira_api_token))
        return cls(config, jira)

    def preflight(self) -> None:
        self._call("Jira authentication check", self.jira.myself)
        self.finding_key_field_id, self.finding_key_field_name = self.resolve_field(self.config.jira_finding_key_field)
        self.issue_type_id = self.resolve_issue_type_id()
        self.verify_create_fields(self.issue_type_id)
        self.search_issues(
            f'project = "{escape_jql_value(self.config.jira_project_key)}" ORDER BY updated DESC',
            max_results=1,
            fields="key",
            context="Jira preflight search",
        )

    def resolve_field(self, configured_field: str) -> tuple[str, str]:
        fields = self._call("Jira field discovery", self.jira.fields)
        if not isinstance(fields, list):
            raise IntegrationError("Jira field discovery did not return a field list.")
        matches = [
            field
            for field in fields
            if field_id(field) == configured_field or field_name(field) == configured_field
        ]
        if not matches:
            normalized_configured = normalize_field_name(configured_field)
            matches = [
                field
                for field in fields
                if normalized_configured and normalize_field_name(field_name(field)) == normalized_configured
            ]
        if not matches:
            matches = self.search_configured_field(configured_field)
        if not matches:
            visible_custom_fields = format_visible_custom_fields(fields)
            raise IntegrationError(
                f"Jira custom field {configured_field!r} was not found in fields visible to "
                f"{self.config.jira_email} and was not found by Jira field search. Set JIRA_FINDING_KEY_FIELD "
                f"to the Jira field's exact display name or id, for example Greenbone Finding Key or customfield_10042. "
                f"Visible custom fields: {visible_custom_fields}"
            )
        if len(matches) > 1:
            matched = ", ".join(format_field(match) for match in matches)
            raise IntegrationError(
                f"Jira returned multiple fields matching {configured_field!r}: {matched}. "
                "Set JIRA_FINDING_KEY_FIELD to the exact customfield_* id."
            )
        resolved_id = field_id(matches[0])
        resolved_name = field_name(matches[0])
        if not resolved_id:
            raise IntegrationError(f"Jira field {configured_field!r} did not expose a usable field id.")
        if not resolved_name:
            raise IntegrationError(f"Jira field {configured_field!r} did not expose a usable field name.")
        return resolved_id, resolved_name

    def search_configured_field(self, configured_field: str) -> list[Any]:
        get_json = getattr(self.jira, "_get_json", None)
        if get_json is None:
            return []
        params: dict[str, Any] = {"type": ["custom"], "maxResults": 50}
        if configured_field.startswith("customfield_"):
            params["id"] = [configured_field]
        else:
            params["query"] = configured_field
        response = self._call("Jira custom field search", get_json, "field/search", params=params)
        matches = normalize_list(response, ("values",))
        if configured_field.startswith("customfield_"):
            return [field for field in matches if field_id(field) == configured_field]
        normalized_configured = normalize_field_name(configured_field)
        return [
            field
            for field in matches
            if field_name(field) == configured_field
            or (normalized_configured and normalize_field_name(field_name(field)) == normalized_configured)
        ]

    def resolve_issue_type_id(self) -> str | None:
        issue_types = self.get_issue_types()
        matches = []
        for issue_type in issue_types:
            issue_type_id = str(value_from(issue_type, "id") or "")
            issue_type_name = str(value_from(issue_type, "name") or "")
            if self.config.jira_issue_type in {issue_type_id, issue_type_name}:
                matches.append(issue_type)
        if not matches:
            raise IntegrationError(
                f"Jira issue type {self.config.jira_issue_type!r} was not found for project "
                f"{self.config.jira_project_key!r}."
            )
        if len(matches) > 1:
            raise IntegrationError(f"Jira returned multiple issue types matching {self.config.jira_issue_type!r}.")
        issue_type_id = value_from(matches[0], "id")
        return str(issue_type_id) if issue_type_id is not None else None

    def get_issue_types(self) -> list[Any]:
        metadata = self._call(
            "Jira create metadata lookup",
            self.jira.createmeta,
            projectKeys=self.config.jira_project_key,
            expand="projects.issuetypes",
        )
        issue_types = createmeta_issue_types(metadata)
        if not issue_types:
            raise IntegrationError(
                f"Jira create metadata did not return issue types for project {self.config.jira_project_key!r}."
            )
        return issue_types

    def verify_create_fields(self, issue_type_id: str | None) -> None:
        create_fields = self.get_create_fields(issue_type_id)
        available = set(create_fields)
        required = {"summary", "description", "labels", self.finding_field_id}
        if self.config.jira_priority:
            required.add("priority")
        missing = sorted(required - available)
        if missing:
            joined = ", ".join(missing)
            raise IntegrationError(
                f"Jira create screen for project {self.config.jira_project_key!r} and issue type "
                f"{self.config.jira_issue_type!r} is missing required field(s): {joined}."
            )

    def get_create_fields(self, issue_type_id: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "projectKeys": self.config.jira_project_key,
            "expand": "projects.issuetypes.fields",
        }
        if issue_type_id is not None:
            kwargs["issuetypeIds"] = [issue_type_id]
        else:
            kwargs["issuetypeNames"] = self.config.jira_issue_type
        metadata = self._call("Jira create metadata field lookup", self.jira.createmeta, **kwargs)
        return createmeta_fields(metadata, self.config.jira_issue_type, issue_type_id)

    def sync_finding(self, finding: Any) -> str:
        matches = self.search_by_finding_key(finding.key)
        if len(matches) > 1:
            raise IntegrationError(f"Jira returned multiple issues for finding key {finding.key}.")
        if not matches:
            issue = self.create_issue(finding)
            return issue_key(issue)
        issue = matches[0]
        self.update_issue(issue, finding)
        return issue_key(issue)

    def search_by_finding_key(self, finding_key: str) -> list[Any]:
        field_name = escape_jql_name(self.finding_field_name)
        key_value = escape_jql_value(finding_key)
        project = escape_jql_value(self.config.jira_project_key)
        jql = f'project = "{project}" AND "{field_name}" = "{key_value}" ORDER BY updated DESC'
        fields = [
            "key",
            "status",
            "statuscategorychangedate",
            "labels",
            "summary",
            "description",
            self.finding_field_id,
        ]
        if self.config.jira_priority:
            fields.append("priority")
        return self.search_issues(jql, max_results=2, fields=",".join(fields), context="Jira finding search")

    def search_issues(self, jql: str, *, max_results: int, fields: str, context: str) -> list[Any]:
        issues = self._call(context, self.jira.search_issues, jql, maxResults=max_results, fields=fields)
        return list(issues)

    def create_issue(self, finding: Any) -> Any:
        description, truncated = finding_text(finding)
        warn_if_truncated(finding, truncated)
        fields: dict[str, Any] = {
            "project": {"key": self.config.jira_project_key},
            "issuetype": issue_type_ref(self.config.jira_issue_type, self.issue_type_id),
            "summary": issue_summary(finding),
            "description": description,
            self.finding_field_id: finding.key,
            "labels": list(self.config.jira_labels),
        }
        if self.config.jira_priority:
            fields["priority"] = {"name": self.config.jira_priority}
        return self._call("Jira issue create", self.jira.create_issue, fields=fields)

    def update_issue(self, issue: Any, finding: Any) -> None:
        existing_text = self.issue_text(issue)
        new_evidence = unseen_evidence(finding.evidence, existing_text)
        if new_evidence:
            comment, truncated = update_comment_text(new_evidence)
            warn_if_truncated(finding, truncated)
            self._call("Jira issue comment", self.jira.add_comment, issue, comment)

        updates = self.issue_field_updates(issue, finding)
        if updates:
            self._call("Jira issue update", issue.update, fields=updates)

        if self.is_closed(issue) and finding.latest_seen > self.closed_at(issue):
            self.reopen_issue(issue)

    def issue_text(self, issue: Any) -> str:
        text_parts = [str(get_issue_field(issue, "description") or "")]
        comments = self._call("Jira comment lookup", self.jira.comments, issue)
        for comment in comments:
            text_parts.append(comment_body(comment))
        return "\n".join(part for part in text_parts if part)

    def issue_field_updates(self, issue: Any, finding: Any) -> dict[str, Any]:
        updates: dict[str, Any] = {}
        current_labels = set(get_issue_field(issue, "labels") or [])
        expected_labels = current_labels | set(self.config.jira_labels)
        if expected_labels != current_labels:
            updates["labels"] = sorted(expected_labels)
        if get_issue_field(issue, self.finding_field_id) != finding.key:
            updates[self.finding_field_id] = finding.key
        return updates

    def is_closed(self, issue: Any) -> bool:
        status = get_issue_field(issue, "status")
        status_name = str(value_from(status, "name") or "")
        category = value_from(status, "statusCategory")
        category_name = str(value_from(category, "name") or "")
        return (
            bool(status_name and status_name in self.config.jira_closed_status_names)
            or bool(category_name and category_name in self.config.jira_closed_status_categories)
        )

    def closed_at(self, issue: Any) -> datetime:
        value = get_issue_field(issue, "statuscategorychangedate")
        if value is None or str(value) == "":
            raise IntegrationError(
                f"Jira issue {issue_key(issue)} is closed, but statuscategorychangedate was not returned. "
                "Jira must return this field so the example can compare the close time with the latest scan time."
            )
        return parse_datetime(str(value), f"Jira issue {issue_key(issue)} statuscategorychangedate")

    def reopen_issue(self, issue: Any) -> None:
        transitions = self._call("Jira transition lookup", self.jira.transitions, issue)
        matching = [
            transition
            for transition in transitions
            if isinstance(transition, dict) and transition.get("name") == self.config.jira_reopen_transition_name
        ]
        if not matching:
            raise IntegrationError(
                f"Jira issue {issue_key(issue)} is closed, but transition "
                f"{self.config.jira_reopen_transition_name!r} is not available."
            )
        transition_id = matching[0].get("id")
        if not transition_id:
            raise IntegrationError(
                f"Jira transition {self.config.jira_reopen_transition_name!r} for issue "
                f"{issue_key(issue)} did not expose an id."
            )
        self._call("Jira issue transition", self.jira.transition_issue, issue, transition_id)

    @property
    def finding_field_id(self) -> str:
        if self.finding_key_field_id is None:
            raise IntegrationError("Jira finding key field id has not been resolved.")
        return self.finding_key_field_id

    @property
    def finding_field_name(self) -> str:
        if self.finding_key_field_name is None:
            raise IntegrationError("Jira finding key field name has not been resolved.")
        return self.finding_key_field_name

    def _call(self, context: str, func: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except IntegrationError:
            raise
        except Exception as exc:
            raise IntegrationError(f"{context} failed: {exc}") from exc


def finding_text(finding: Any) -> tuple[str, bool]:
    first_result = finding.evidence[0].result
    nvt = first_result.get("nvt") if isinstance(first_result.get("nvt"), dict) else {}
    cves = nvt.get("cves") if isinstance(nvt.get("cves"), list) else []
    lines = [
        f"Finding key: {finding.key}",
        f"Latest seen: {finding.latest_seen.isoformat()}",
        f"NVT OID: {finding.nvt_oid}",
        f"NVT name: {nvt.get('name') or first_result.get('name') or 'n/a'}",
        f"Severity: {first_result.get('severity', 'n/a')}",
        f"Threat: {first_result.get('threat', 'n/a')}",
        f"Host: {finding.host}",
        f"Port: {finding.port}",
    ]
    if cves:
        lines.append(f"CVEs: {', '.join(str(cve) for cve in cves)}")
    if first_result.get("description"):
        lines.extend(["", "Description:", str(first_result["description"])])

    lines.extend(["", "Evidence:"])
    evidence_items = []
    truncated = len(finding.evidence) > MAX_EVIDENCE_ROWS
    for index, evidence in enumerate(finding.evidence[:MAX_EVIDENCE_ROWS], start=1):
        evidence_items.append(
            f"#{index}: {evidence_marker(evidence)}, severity {evidence.result.get('severity', 'n/a')}"
        )
    if truncated:
        evidence_items.append(f"Evidence truncated to {MAX_EVIDENCE_ROWS} of {len(finding.evidence)} result rows.")
    lines.extend(f"- {item}" for item in evidence_items)
    return "\n".join(lines), truncated


def update_comment_text(evidence: list[Any]) -> tuple[str, bool]:
    truncated = len(evidence) > MAX_EVIDENCE_ROWS
    lines = ["Finding still present.", "", "New evidence:"]
    lines.extend(f"- {evidence_marker(item)}" for item in evidence[:MAX_EVIDENCE_ROWS])
    if truncated:
        lines.append(f"- Evidence truncated to {MAX_EVIDENCE_ROWS} of {len(evidence)} new result rows.")
    return "\n".join(lines), truncated


def unseen_evidence(evidence: list[Any], existing_text: str) -> list[Any]:
    return [item for item in evidence if evidence_marker(item) not in existing_text]


def evidence_marker(evidence: Any) -> str:
    result_id = evidence.result.get("id") or "n/a"
    return f"report {evidence.report_id}, result {result_id}, scan start {evidence.scan_start.isoformat()}"


def warn_if_truncated(finding: Any, truncated: bool) -> None:
    if truncated:
        print(
            f"Warning: Jira content for finding {finding.key!r} was truncated to "
            f"{MAX_EVIDENCE_ROWS} evidence rows.",
            file=sys.stderr,
        )


def issue_summary(finding: Any) -> str:
    first_result = finding.evidence[0].result
    nvt = first_result.get("nvt") if isinstance(first_result.get("nvt"), dict) else {}
    name = nvt.get("name") or first_result.get("name") or finding.nvt_oid
    summary = f"{name} on {finding.host} {finding.port}"
    return summary[:255]


def issue_type_ref(configured: str, resolved_id: str | None) -> dict[str, str]:
    if resolved_id is not None:
        return {"id": resolved_id}
    if configured.isdigit():
        return {"id": configured}
    return {"name": configured}


def normalize_list(value: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []


def createmeta_issue_types(metadata: Any) -> list[Any]:
    issue_types: list[Any] = []
    if not isinstance(metadata, dict):
        return issue_types
    for project in normalize_list(metadata, ("projects",)):
        issue_types.extend(normalize_list(project, ("issuetypes", "issueTypes")))
    return issue_types


def createmeta_fields(metadata: Any, configured_issue_type: str, issue_type_id: str | None) -> dict[str, Any]:
    for issue_type in createmeta_issue_types(metadata):
        current_id = str(value_from(issue_type, "id") or "")
        current_name = str(value_from(issue_type, "name") or "")
        if issue_type_id is not None and current_id != issue_type_id:
            continue
        if issue_type_id is None and configured_issue_type not in {current_id, current_name}:
            continue
        fields = value_from(issue_type, "fields")
        if isinstance(fields, dict):
            return fields
    return {}


def field_id(field: Any) -> str:
    value = value_from(field, "id")
    return str(value) if value is not None else ""


def field_name(field: Any) -> str:
    value = value_from(field, "name")
    return str(value) if value is not None else ""


def normalize_field_name(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def format_visible_custom_fields(fields: list[Any]) -> str:
    custom_fields = [
        format_field(field)
        for field in fields
        if field_id(field).startswith("customfield_")
    ]
    if not custom_fields:
        return "none"
    return ", ".join(custom_fields[:20])


def format_field(field: Any) -> str:
    return f"{field_name(field) or '<unnamed>'} ({field_id(field) or '<no id>'})"


def value_from(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def get_issue_field(issue: Any, name: str) -> Any:
    if hasattr(issue, "get_field"):
        try:
            return issue.get_field(name)
        except Exception:
            pass
    fields = getattr(issue, "fields", None)
    if fields is not None and hasattr(fields, name):
        return getattr(fields, name)
    raw = getattr(issue, "raw", None)
    if isinstance(raw, dict):
        raw_fields = raw.get("fields")
        if isinstance(raw_fields, dict):
            return raw_fields.get(name)
    return None


def comment_body(comment: Any) -> str:
    body = value_from(comment, "body")
    if body is None:
        raw = getattr(comment, "raw", None)
        if isinstance(raw, dict):
            body = raw.get("body")
    if body is None:
        return ""
    return str(body)


def issue_key(issue: Any) -> str:
    key = getattr(issue, "key", None)
    if key:
        return str(key)
    raw = getattr(issue, "raw", None)
    if isinstance(raw, dict) and raw.get("key"):
        return str(raw["key"])
    return str(issue)


def escape_jql_name(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def escape_jql_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
