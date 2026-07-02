from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gateway
import jira_client
import utils
import workflow


def base_env(**overrides: str) -> dict[str, str]:
    values = {
        "GVM_GATEWAY_BASE_URL": "http://gvm.example",
        "GVM_GATEWAY_USERNAME": "admin",
        "GVM_GATEWAY_PASSWORD": "secret",
        "JIRA_SITE_URL": "https://jira.example.atlassian.net",
        "JIRA_EMAIL": "greenbone@example.com",
        "JIRA_API_TOKEN": "jira-secret",
        "JIRA_PROJECT_KEY": "SEC",
        "JIRA_REOPEN_TRANSITION_NAME": "Reopen",
    }
    values.update(overrides)
    return values


def write_env(testcase: unittest.TestCase, values: dict[str, str]) -> Path:
    temp_dir = tempfile.TemporaryDirectory()
    testcase.addCleanup(temp_dir.cleanup)
    path = Path(temp_dir.name) / ".env"
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()), encoding="utf-8")
    return path


def sample_finding(evidence_count: int = 1) -> workflow.Finding:
    evidence = []
    for index in range(evidence_count):
        evidence.append(
            workflow.Evidence(
                report_id=f"report-{index}",
                scan_start=datetime(2026, 7, 1, 11, index, 0, tzinfo=timezone.utc),
                result={
                    "id": f"result-{index}",
                    "name": "Example NVT",
                    "host": "192.0.2.10",
                    "port": "80/tcp",
                    "severity": 7.0,
                    "threat": "High",
                    "description": "Example description",
                    "nvt": {"oid": "1.2.3", "name": "Example NVT", "cves": ["CVE-2026-0001"]},
                },
            )
        )
    return workflow.Finding(
        key="1.2.3|192.0.2.10|80/tcp",
        nvt_oid="1.2.3",
        host="192.0.2.10",
        port="80/tcp",
        latest_seen=evidence[-1].scan_start,
        evidence=evidence,
    )


class FakeHttp:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def request_json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


class FakeIssue:
    def __init__(
        self,
        key: str = "SEC-1",
        labels: list[str] | None = None,
        finding_key: str = "1.2.3|192.0.2.10|80/tcp",
        status: dict[str, Any] | None = None,
        statuscategorychangedate: str | None = "2026-07-01T10:00:00.000+0000",
    ) -> None:
        self.key = key
        fields = {
            "labels": labels or [],
            "customfield_10042": finding_key,
            "status": status or {"name": "Done", "statusCategory": {"name": "Done"}},
        }
        if statuscategorychangedate is not None:
            fields["statuscategorychangedate"] = statuscategorychangedate
        self.raw = {"fields": fields}
        self.updated_fields: list[dict[str, Any]] = []

    def get_field(self, name: str) -> Any:
        return self.raw["fields"].get(name)

    def update(self, *, fields: dict[str, Any]) -> None:
        self.updated_fields.append(fields)
        self.raw["fields"].update(fields)


class FakeJira:
    def __init__(self) -> None:
        self.search_results: list[Any] = []
        self.created_fields: dict[str, Any] | None = None
        self.comments: list[tuple[Any, Any]] = []
        self.transitioned: list[tuple[Any, str]] = []
        self.searches: list[dict[str, Any]] = []
        self.transition_values = [{"id": "31", "name": "Reopen"}]
        self.field_search_response: dict[str, Any] = {"values": []}

    def myself(self) -> dict[str, str]:
        return {"accountId": "abc"}

    def fields(self) -> list[dict[str, str]]:
        return [
            {"id": "summary", "name": "Summary"},
            {"id": "customfield_10042", "name": "GreenboneFindingKey"},
        ]

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path != "field/search":
            raise AssertionError(f"Unexpected SDK JSON path {path}")
        return self.field_search_response

    def createmeta(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "projects": [
                {
                    "key": "SEC",
                    "issuetypes": [
                        {
                            "id": "10001",
                            "name": "Task",
                            "fields": {
                                "summary": {},
                                "description": {},
                                "labels": {},
                                "customfield_10042": {},
                            },
                        }
                    ],
                }
            ]
        }

    def search_issues(self, jql: str, *, maxResults: int, fields: str) -> list[Any]:
        self.searches.append({"jql": jql, "maxResults": maxResults, "fields": fields})
        return self.search_results

    def create_issue(self, *, fields: dict[str, Any]) -> FakeIssue:
        self.created_fields = fields
        return FakeIssue()

    def add_comment(self, issue: Any, comment: Any) -> None:
        self.comments.append((issue, comment))

    def transitions(self, issue: Any) -> list[dict[str, str]]:
        return self.transition_values

    def transition_issue(self, issue: Any, transition_id: str) -> None:
        self.transitioned.append((issue, transition_id))


class ConfigTests(unittest.TestCase):
    def test_config_load_applies_jira_defaults(self) -> None:
        """Default values keep the example runnable with a small .env."""
        config = utils.Config.load(write_env(self, base_env()))

        self.assertEqual("Task", config.jira_issue_type)
        self.assertEqual("GreenboneFindingKey", config.jira_finding_key_field)
        self.assertEqual(("greenbone", "gvm"), config.jira_labels)
        self.assertEqual(("Done",), config.jira_closed_status_categories)
        self.assertEqual(24, config.jira_lookback_hours)
        self.assertEqual(4.0, config.jira_min_severity)

    def test_config_load_rejects_versioned_urls(self) -> None:
        """Users configure service roots; the clients append API paths internally."""
        with self.assertRaisesRegex(utils.IntegrationError, "must not include /api/v1"):
            utils.Config.load(write_env(self, base_env(GVM_GATEWAY_BASE_URL="http://gvm.example/api/v1")))

        with self.assertRaisesRegex(utils.IntegrationError, "must not include /rest/api/3"):
            utils.Config.load(write_env(self, base_env(JIRA_SITE_URL="https://jira.example/rest/api/3")))

    def test_config_load_rejects_non_http_urls(self) -> None:
        """Configured service roots must be network URLs accepted by the HTTP client."""
        with self.assertRaisesRegex(utils.IntegrationError, "GVM_GATEWAY_BASE_URL must be an HTTP or HTTPS URL"):
            utils.Config.load(write_env(self, base_env(GVM_GATEWAY_BASE_URL="file:///tmp/gvm")))

        with self.assertRaisesRegex(utils.IntegrationError, "JIRA_SITE_URL must be an HTTP or HTTPS URL"):
            utils.Config.load(write_env(self, base_env(JIRA_SITE_URL="file:///tmp/jira")))

    def test_parse_datetime_accepts_jira_timezone_offset(self) -> None:
        """Jira Cloud timestamps use +0000 offsets, which must compare with scan times."""
        parsed = utils.parse_datetime("2026-07-01T10:00:00.000+0000", "Jira timestamp")

        self.assertEqual(datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc), parsed)


class GvmClientTests(unittest.TestCase):
    def test_recent_reports_apply_server_and_client_side_cutoff(self) -> None:
        """The report filter is used, but stale reports are still rejected client-side."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp(
            [
                {
                    "data": [
                        {"id": "recent", "scanStart": "2026-07-01T11:00:00Z"},
                        {"id": "old", "scanStart": "2026-06-30T10:59:59Z"},
                    ],
                    "pagination": {"page": 1, "perPage": 1000, "total": 2, "totalPages": 1},
                }
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        reports = client.get_recent_reports(datetime(2026, 7, 1, 11, 0, 0, tzinfo=timezone.utc))

        self.assertEqual(["recent"], [report["id"] for report in reports])
        self.assertIn("scan_start%3E2026-06-30T11%3A00%3A00Z", fake_http.calls[0]["url"])

    def test_report_results_ignore_threshold_and_lower_severity(self) -> None:
        """The Jira example only syncs results with severity strictly above the threshold."""
        config = utils.Config.load(write_env(self, base_env(JIRA_MIN_SEVERITY="4.0")))
        fake_http = FakeHttp(
            [
                {
                    "data": [
                        {"id": "ignored", "severity": 4.0},
                        {"id": "kept", "severity": 4.1},
                    ],
                    "pagination": {"page": 1, "perPage": 1000, "total": 2, "totalPages": 1},
                }
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        results = client.get_report_results("report-1")

        self.assertEqual(["kept"], [result["id"] for result in results])


class FindingAggregationTests(unittest.TestCase):
    def test_aggregate_findings_groups_by_nvt_host_and_opaque_port(self) -> None:
        """One Jira issue represents all evidence with the same stable finding key."""
        report = {"id": "report-1", "scanStart": "2026-07-01T11:00:00Z"}
        result = {
            "id": "result-1",
            "host": "192.0.2.10",
            "port": "80/tcp",
            "nvt": {"oid": "1.2.3"},
        }

        findings = workflow.aggregate_findings([(report, result), (report, dict(result, id="result-2"))])

        self.assertEqual(1, len(findings))
        self.assertEqual("1.2.3|192.0.2.10|80/tcp", findings[0].key)
        self.assertEqual(2, len(findings[0].evidence))

    def test_aggregate_findings_fails_when_required_identity_field_is_missing(self) -> None:
        """Missing identity components would create unstable Jira correlation."""
        report = {"id": "report-1", "scanStart": "2026-07-01T11:00:00Z"}
        result = {"id": "result-1", "host": "192.0.2.10", "nvt": {"oid": "1.2.3"}}

        with self.assertRaisesRegex(utils.IntegrationError, "missing required field port"):
            workflow.aggregate_findings([(report, result)])


class JiraClientTests(unittest.TestCase):
    def test_preflight_resolves_custom_field_and_checks_create_metadata(self) -> None:
        """Preflight validates Jira setup before any finding creates an issue."""
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), FakeJira())

        client.preflight()

        self.assertEqual("customfield_10042", client.finding_key_field_id)
        self.assertEqual("GreenboneFindingKey", client.finding_key_field_name)
        self.assertEqual("10001", client.issue_type_id)

    def test_preflight_resolves_custom_field_by_normalized_display_name(self) -> None:
        """Jira admins often create spaced display names while .env uses the compact default."""
        fake_jira = FakeJira()
        fake_jira.fields = lambda: [  # type: ignore[method-assign]
            {"id": "customfield_10042", "name": "Greenbone Finding Key"},
        ]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)

        client.preflight()
        client.search_by_finding_key("1.2.3|192.0.2.10|80/tcp")

        self.assertEqual("customfield_10042", client.finding_key_field_id)
        self.assertEqual("Greenbone Finding Key", client.finding_key_field_name)
        self.assertIn('"Greenbone Finding Key"', fake_jira.searches[-1]["jql"])

    def test_preflight_resolves_custom_field_by_id(self) -> None:
        """Using customfield_* avoids ambiguity when Jira has similar custom field names."""
        config = utils.Config.load(write_env(self, base_env(JIRA_FINDING_KEY_FIELD="customfield_10042")))
        client = jira_client.JiraIssueClient(config, FakeJira())

        client.preflight()

        self.assertEqual("customfield_10042", client.finding_key_field_id)
        self.assertEqual("GreenboneFindingKey", client.finding_key_field_name)

    def test_preflight_resolves_custom_field_by_paginated_field_search(self) -> None:
        """Fields omitted from visible-fields can still be diagnosed through Jira field search."""
        fake_jira = FakeJira()
        fake_jira.fields = lambda: [  # type: ignore[method-assign]
            {"id": "customfield_10035", "name": "Vulnerability"},
        ]
        fake_jira.field_search_response = {
            "values": [{"id": "customfield_10073", "name": "GreenboneFindingKey"}],
        }
        fake_jira.createmeta = lambda **kwargs: {  # type: ignore[method-assign]
            "projects": [
                {
                    "issuetypes": [
                        {
                            "id": "10001",
                            "name": "Task",
                            "fields": {
                                "summary": {},
                                "description": {},
                                "labels": {},
                                "customfield_10073": {},
                            },
                        }
                    ]
                }
            ]
        }
        config = utils.Config.load(write_env(self, base_env(JIRA_FINDING_KEY_FIELD="customfield_10073")))
        client = jira_client.JiraIssueClient(config, fake_jira)

        client.preflight()

        self.assertEqual("customfield_10073", client.finding_key_field_id)
        self.assertEqual("GreenboneFindingKey", client.finding_key_field_name)

    def test_preflight_reports_create_screen_when_field_search_finds_field(self) -> None:
        """Existing fields still must be available on the Task create screen."""
        fake_jira = FakeJira()
        fake_jira.fields = lambda: []  # type: ignore[method-assign]
        fake_jira.field_search_response = {
            "values": [{"id": "customfield_10073", "name": "GreenboneFindingKey"}],
        }
        config = utils.Config.load(write_env(self, base_env(JIRA_FINDING_KEY_FIELD="customfield_10073")))
        client = jira_client.JiraIssueClient(config, fake_jira)

        with self.assertRaisesRegex(utils.IntegrationError, "create screen.*customfield_10073"):
            client.preflight()

    def test_preflight_fails_when_custom_field_name_is_duplicated(self) -> None:
        """Ambiguous custom fields would make JQL lookup and issue updates unsafe."""
        fake_jira = FakeJira()
        fake_jira.fields = lambda: [  # type: ignore[method-assign]
            {"id": "customfield_10042", "name": "GreenboneFindingKey"},
            {"id": "customfield_10043", "name": "GreenboneFindingKey"},
        ]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)

        with self.assertRaisesRegex(utils.IntegrationError, "multiple fields"):
            client.preflight()

    def test_sync_finding_creates_issue_when_no_match_exists(self) -> None:
        """New findings create Jira issues with the stable key custom field set."""
        fake_jira = FakeJira()
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)
        client.preflight()

        issue_key = client.sync_finding(sample_finding())

        self.assertEqual("SEC-1", issue_key)
        self.assertEqual("1.2.3|192.0.2.10|80/tcp", fake_jira.created_fields["customfield_10042"])
        self.assertEqual({"id": "10001"}, fake_jira.created_fields["issuetype"])
        self.assertEqual("Example NVT on 192.0.2.10 80/tcp", fake_jira.created_fields["summary"])
        self.assertEqual(["greenbone", "gvm"], fake_jira.created_fields["labels"])
        self.assertIsInstance(fake_jira.created_fields["description"], str)
        self.assertIn("Finding key: 1.2.3|192.0.2.10|80/tcp", fake_jira.created_fields["description"])
        self.assertNotIn("Greenbone finding observed by GVM REST API.", fake_jira.created_fields["description"])

    def test_sync_finding_does_not_reopen_when_issue_was_closed_after_latest_scan(self) -> None:
        """Manual closure after the last scan suppresses reopening until a newer scan sees it."""
        fake_jira = FakeJira()
        closed_issue = FakeIssue(labels=["greenbone"], statuscategorychangedate="2026-07-01T12:00:00.000+0000")
        fake_jira.search_results = [closed_issue]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)
        client.preflight()

        issue_key = client.sync_finding(sample_finding())

        self.assertEqual("SEC-1", issue_key)
        self.assertEqual(1, len(fake_jira.comments))
        self.assertEqual([], fake_jira.transitioned)
        self.assertIn({"labels": ["greenbone", "gvm"]}, closed_issue.updated_fields)

    def test_sync_finding_reopens_when_latest_scan_is_newer_than_close_time(self) -> None:
        """Closed issues reopen only when a later scan observes the same finding again."""
        fake_jira = FakeJira()
        closed_issue = FakeIssue(labels=["greenbone"], statuscategorychangedate="2026-07-01T10:00:00.000+0000")
        fake_jira.search_results = [closed_issue]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)
        client.preflight()

        issue_key = client.sync_finding(sample_finding())

        self.assertEqual("SEC-1", issue_key)
        self.assertEqual(1, len(fake_jira.comments))
        self.assertEqual([("SEC-1", "31")], [(issue.key, transition_id) for issue, transition_id in fake_jira.transitioned])
        self.assertIn({"labels": ["greenbone", "gvm"]}, closed_issue.updated_fields)

    def test_sync_finding_fails_when_closed_issue_has_no_close_timestamp(self) -> None:
        """Without a Jira close time the example cannot safely decide whether to reopen."""
        fake_jira = FakeJira()
        fake_jira.search_results = [FakeIssue(statuscategorychangedate=None)]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)
        client.preflight()

        with self.assertRaisesRegex(utils.IntegrationError, "statuscategorychangedate"):
            client.sync_finding(sample_finding())

    def test_sync_finding_fails_when_multiple_issues_match_key(self) -> None:
        """Finding identity must remain one-to-one with Jira issues."""
        fake_jira = FakeJira()
        fake_jira.search_results = [FakeIssue("SEC-1"), FakeIssue("SEC-2")]
        client = jira_client.JiraIssueClient(utils.Config.load(write_env(self, base_env())), fake_jira)
        client.preflight()

        with self.assertRaisesRegex(utils.IntegrationError, "multiple issues"):
            client.sync_finding(sample_finding())

    def test_finding_text_truncates_large_evidence_sets(self) -> None:
        """Generated Jira content stays compact when scans produce many result rows."""
        text, truncated = jira_client.finding_text(sample_finding(evidence_count=12))

        self.assertTrue(truncated)
        self.assertIsInstance(text, str)
        self.assertIn("Evidence truncated", text)


if __name__ == "__main__":
    unittest.main()
