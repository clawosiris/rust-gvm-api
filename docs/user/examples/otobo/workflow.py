from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from gateway import GvmClient
from otobo import OtoboClient, require_ticket_state
from utils import Config, IntegrationError, HttpJsonClient, parse_datetime, require_text


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

    sync_error: IntegrationError | None = None
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
    except IntegrationError as exc:
        sync_error = exc
        raise
    finally:
        try:
            gvm.close_session()
        except IntegrationError as cleanup_error:
            if sync_error is None:
                raise
            print(f"Warning: {cleanup_error}", file=sys.stderr)


def sync_cmdb_hosts(otobo: OtoboClient, hosts: list[dict[str, Any]]) -> list[SyncedConfigItem]:
    synced = []
    for host in hosts:
        host_id = require_text(host, "id", "GVM host")
        config_item_ids = otobo.config_item_search(host_id)
        if len(config_item_ids) > 1:
            raise IntegrationError(f"OTOBO returned multiple config items for GVM host id {host_id}.")
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
                raise IntegrationError(
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
            raise IntegrationError(f"Severity-eligible result {result.get('id')} is missing nvt data.")
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
        raise IntegrationError(f"OTOBO returned multiple tickets for finding key {finding.key}.")
    if not ticket_ids:
        otobo.ticket_create(finding, config_item_id)
        return

    ticket_id = ticket_ids[0]
    ticket = otobo.ticket_get(ticket_id)
    state = require_ticket_state(ticket, ticket_id)
    reopen = state in config.closed_states
    otobo.ticket_update(ticket_id, finding, reopen, config_item_id)
