from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from gateway import GvmClient
from jira_client import JiraIssueClient
from utils import Config, ExampleError, HttpJsonClient, parse_datetime, require_text


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
    jira = JiraIssueClient.connect(config)

    jira.preflight()
    gvm.create_session()

    sync_error: ExampleError | None = None
    try:
        reports = gvm.get_recent_reports(datetime.now(timezone.utc))
        report_results = []
        for report in reports:
            report_id = require_text(report, "id", "GVM report")
            for result in gvm.get_report_results(report_id):
                report_results.append((report, result))

        findings = aggregate_findings(report_results)
        for finding in findings:
            jira.sync_finding(finding)

        print(f"Synchronization complete: {len(reports)} report(s), {len(findings)} finding(s).")
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
