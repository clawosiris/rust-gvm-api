from __future__ import annotations

import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import gateway
import otobo
import requests
import utils
import workflow


def base_env(**overrides: str) -> dict[str, str]:
    values = {
        "GVM_GATEWAY_BASE_URL": "http://gvm.example",
        "GVM_GATEWAY_USERNAME": "admin",
        "GVM_GATEWAY_PASSWORD": "secret",
        "OTOBO_BASE_URL": "http://otobo.example/otobo/nph-genericinterface.pl/Webservice",
        "OTOBO_WEB_SERVICE": "Greenbone",
        "OTOBO_USERNAME": "root@localhost",
        "OTOBO_PASSWORD": "otobo-secret",
        "OTOBO_OPERATION_TICKET_SEARCH": "TicketSearch",
        "OTOBO_OPERATION_TICKET_GET": "TicketGet",
        "OTOBO_OPERATION_TICKET_CREATE": "TicketCreate",
        "OTOBO_OPERATION_TICKET_UPDATE": "TicketUpdate",
        "OTOBO_OPERATION_CONFIG_ITEM_SEARCH": "ConfigItemSearch",
        "OTOBO_OPERATION_CONFIG_ITEM_UPSERT": "ConfigItemUpsert",
        "OTOBO_FINDING_KEY_FIELD": "GreenboneFindingKey",
        "OTOBO_TICKET_QUEUE": "Raw",
        "OTOBO_TICKET_CUSTOMER_USER": "greenbone@example.com",
        "OTOBO_TICKET_STATE_NEW": "new",
        "OTOBO_TICKET_PRIORITY": "3 normal",
        "OTOBO_TICKET_ARTICLE_SENDER_TYPE": "agent",
        "OTOBO_TICKET_ARTICLE_TYPE": "note-internal",
        "OTOBO_CLOSED_STATES": "closed successful, closed unsuccessful",
        "OTOBO_REOPEN_STATE": "open",
        "OTOBO_CONFIG_ITEM_CLASS": "Computer",
        "OTOBO_CONFIG_ITEM_DEPLOYMENT_STATE": "Production",
        "OTOBO_CONFIG_ITEM_INCIDENT_STATE": "Operational",
        "OTOBO_CONFIG_ITEM_EXTERNAL_KEY_ATTRIBUTE": "GreenboneHostID",
        "OTOBO_CONFIG_ITEM_NAME_ATTRIBUTE": "Name",
        "OTOBO_CONFIG_ITEM_HOSTNAME_ATTRIBUTE": "Computer-FQDN",
        "OTOBO_CONFIG_ITEM_OS_ATTRIBUTE": "Computer-OperatingSystem",
    }
    values.update(overrides)
    return values


def write_env(testcase: unittest.TestCase, values: dict[str, str]) -> Path:
    temp_dir = tempfile.TemporaryDirectory()
    testcase.addCleanup(temp_dir.cleanup)
    path = Path(temp_dir.name) / ".env"
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()), encoding="utf-8")
    return path


def sample_finding() -> workflow.Finding:
    return workflow.Finding(
        key="1.2.3|192.0.2.10|80/tcp",
        nvt_oid="1.2.3",
        host="192.0.2.10",
        port="80/tcp",
        latest_seen=datetime(2026, 7, 1, 11, 0, 0, tzinfo=timezone.utc),
        evidence=[
            workflow.Evidence(
                report_id="report-a",
                scan_start=datetime(2026, 7, 1, 11, 0, 0, tzinfo=timezone.utc),
                result={
                    "id": "result-a",
                    "name": "Example NVT",
                    "host": "192.0.2.10",
                    "port": "80/tcp",
                    "severity": 7.0,
                    "threat": "High",
                    "description": "Example description",
                    "nvt": {"oid": "1.2.3", "name": "Example NVT", "cves": ["CVE-2026-0001"]},
                },
            )
        ],
    )


class FakeHttp:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def request_json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


class IsolatedEnvTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env_patch = mock.patch.dict("os.environ", {}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)


class ConfigTests(IsolatedEnvTest):
    def test_config_load_trims_closed_states_for_reopen_matching(self) -> None:
        """Closed-state parsing protects the ticket reopen contract from whitespace in .env."""
        path = write_env(self, base_env(OTOBO_CLOSED_STATES=" closed successful ,closed unsuccessful "))

        config = utils.Config.load(path)

        self.assertEqual(("closed successful", "closed unsuccessful"), config.closed_states)

    def test_config_load_rejects_gateway_base_url_with_versioned_api_path(self) -> None:
        """Gateway env vars match shell examples, so /api/v1 is appended by the script."""
        path = write_env(self, base_env(GVM_GATEWAY_BASE_URL="http://gvm.example/api/v1"))

        with self.assertRaisesRegex(utils.IntegrationError, "must not include /api/v1"):
            utils.Config.load(path)

    def test_config_load_rejects_non_http_urls(self) -> None:
        """Configured service roots must be network URLs accepted by the HTTP client."""
        path = write_env(self, base_env(GVM_GATEWAY_BASE_URL="file:///tmp/gvm"))

        with self.assertRaisesRegex(utils.IntegrationError, "GVM_GATEWAY_BASE_URL must be an HTTP or HTTPS URL"):
            utils.Config.load(path)

        path = write_env(self, base_env(OTOBO_BASE_URL="file:///tmp/otobo"))

        with self.assertRaisesRegex(utils.IntegrationError, "OTOBO_BASE_URL must be an HTTP or HTTPS URL"):
            utils.Config.load(path)

    def test_config_load_does_not_require_unused_ticket_open_state(self) -> None:
        """Reopen behavior is controlled by OTOBO_REOPEN_STATE, avoiding duplicate state knobs."""
        values = base_env()
        values.pop("OTOBO_TICKET_STATE_OPEN", None)
        path = write_env(self, values)

        config = utils.Config.load(path)

        self.assertEqual("open", config.reopen_state)


class HttpErrorFormattingTests(IsolatedEnvTest):
    def test_empty_otobo_http_error_names_url_and_troubleshooting_hint(self) -> None:
        """Empty OTOBO 500 responses still need enough context to fix the setup."""
        message = utils.format_http_failure(
            "OTOBO TicketSearch",
            "http://otobo.example/otobo/nph-genericinterface.pl/Webservice/Greenbone/TicketSearch",
            500,
            "",
        )

        self.assertIn("OTOBO TicketSearch failed with HTTP 500", message)
        self.assertIn("http://otobo.example/otobo/nph-genericinterface.pl/Webservice/Greenbone/TicketSearch", message)
        self.assertIn("empty response body", message)
        self.assertIn("Generic Interface web service route", message)
        self.assertNotIn("HTTP 500:", message)

    def test_non_empty_http_error_keeps_response_body(self) -> None:
        """When the server does explain the failure, preserve that detail in the error."""
        message = utils.format_http_failure(
            "GVM GET /api/v1/hosts page 1",
            "http://gvm.example/api/v1/hosts?page=1&perPage=1000",
            502,
            '{"detail":"backend unavailable"}',
        )

        self.assertIn('Response body: {"detail":"backend unavailable"}', message)

    def test_request_timeout_is_reported_without_traceback(self) -> None:
        """Socket timeouts should become actionable example errors, not raw tracebacks."""
        client = utils.HttpJsonClient(timeout=1)

        with mock.patch("requests.request", side_effect=requests.Timeout("timed out")):
            with self.assertRaisesRegex(utils.IntegrationError, "timed out after 1 seconds"):
                client.request_json("GET", "http://gvm.example/api/v1/hosts", context="GVM hosts")


class GvmClientTests(IsolatedEnvTest):
    def test_paginated_host_reads_continue_until_total_pages(self) -> None:
        """GVM pagination must read every page, not just the first response."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp(
            [
                {"data": [{"id": "host-1"}], "pagination": {"page": 1, "perPage": 1000, "total": 2, "totalPages": 2}},
                {"data": [{"id": "host-2"}], "pagination": {"page": 2, "perPage": 1000, "total": 2, "totalPages": 2}},
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        hosts = client.get_hosts()

        self.assertEqual([{"id": "host-1"}, {"id": "host-2"}], hosts)
        self.assertIn("page=1", fake_http.calls[0]["url"])
        self.assertIn("page=2", fake_http.calls[1]["url"])

    def test_paginated_reads_fail_on_malformed_data_items(self) -> None:
        """Malformed GVM page entries are data mapping failures, not ignorable rows."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp(
            [
                {
                    "data": [{"id": "host-1"}, None],
                    "pagination": {"page": 1, "perPage": 1000, "total": 2, "totalPages": 1},
                }
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        with self.assertRaisesRegex(utils.IntegrationError, "malformed data item at index 1"):
            client.get_hosts()

    def test_paginated_reads_fail_when_pagination_is_missing(self) -> None:
        """Paginated GVM endpoints must expose pagination so all pages can be read."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp([{"data": [{"id": "host-1"}]}])
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        with self.assertRaisesRegex(utils.IntegrationError, "pagination object"):
            client.get_hosts()

    def test_paginated_reads_fail_when_total_pages_is_not_numeric(self) -> None:
        """Malformed pagination totals would make page traversal unreliable."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp(
            [
                {
                    "data": [{"id": "host-1"}],
                    "pagination": {"page": 1, "perPage": 1000, "total": 1, "totalPages": "many"},
                }
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        with self.assertRaisesRegex(utils.IntegrationError, "pagination.totalPages must be an integer"):
            client.get_hosts()

    def test_recent_reports_apply_client_side_scan_start_cutoff(self) -> None:
        """The report filter is not trusted alone; stale reports are ignored client-side."""
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

    def test_recent_reports_fail_when_scan_start_is_missing(self) -> None:
        """Returned reports without scanStart cannot be checked against the 24-hour contract."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp(
            [
                {
                    "data": [{"id": "missing-scan-start"}],
                    "pagination": {"page": 1, "perPage": 1000, "total": 1, "totalPages": 1},
                }
            ]
        )
        client = gateway.GvmClient(config, fake_http)  # type: ignore[arg-type]
        client.session_token = "token"

        with self.assertRaisesRegex(utils.IntegrationError, "scanStart"):
            client.get_recent_reports(datetime(2026, 7, 1, 11, 0, 0, tzinfo=timezone.utc))


class OtoboClientTests(IsolatedEnvTest):
    def test_operation_url_uses_configured_web_service_and_operation_path(self) -> None:
        """OTOBO route names are administrator-configured and must not be hard-coded."""
        config = utils.Config.load(write_env(self, base_env(OTOBO_OPERATION_TICKET_SEARCH="Custom/TicketSearch")))
        client = otobo.OtoboClient(config, FakeHttp([]))  # type: ignore[arg-type]

        url = client.operation_url(config.op_ticket_search)

        self.assertEqual(
            "http://otobo.example/otobo/nph-genericinterface.pl/Webservice/Greenbone/Custom/TicketSearch",
            url,
        )

    def test_call_adds_direct_credentials_to_each_generic_interface_payload(self) -> None:
        """The example uses per-request OTOBO credentials instead of an OTOBO session."""
        config = utils.Config.load(write_env(self, base_env()))
        fake_http = FakeHttp([{"TicketID": []}])
        client = otobo.OtoboClient(config, fake_http)  # type: ignore[arg-type]

        client.ticket_search_by_finding_key("oid|host|port")

        payload = fake_http.calls[0]["payload"]
        self.assertEqual("root@localhost", payload["UserLogin"])
        self.assertEqual("otobo-secret", payload["Password"])
        self.assertIn("DynamicField_GreenboneFindingKey", payload)

    def test_ticket_search_treats_empty_otobo_response_as_no_match(self) -> None:
        """OTOBO TicketSearch may map a valid no-match response to an empty JSON object."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{}]))  # type: ignore[arg-type]

        ticket_ids = client.ticket_search_by_finding_key("oid|host|port")

        self.assertEqual([], ticket_ids)

    def test_ticket_search_rejects_non_empty_unrecognized_response_shape(self) -> None:
        """A non-empty search response without ticket identifiers is an unsafe mapping shape."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{"Unexpected": []}]))  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "missing expected response field"):
            client.ticket_search_by_finding_key("oid|host|port")

    def test_preflight_rejects_otobo_error_payloads(self) -> None:
        """OTOBO can report setup failures inside JSON bodies, so those must be fatal."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp([{"Error": {"ErrorMessage": "Unknown dynamic field"}}]),
        )  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "Unknown dynamic field"):
            client.preflight()

    def test_preflight_rejects_unrecognized_config_item_search_response_shape(self) -> None:
        """The CMDB smoke check must validate the config item operation response shape."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{"TicketID": []}, {"Unexpected": []}]))  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "ConfigItemSearch response is missing"):
            client.preflight()

    def test_preflight_accepts_empty_no_match_search_responses(self) -> None:
        """Valid harmless preflight searches may return empty objects or empty result lists."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{}, {}]))  # type: ignore[arg-type]

        client.preflight()

    def test_config_item_search_uses_dynamic_field_search_parameter(self) -> None:
        """OTOBO 11 ConfigItemSearch expects DynamicField_<name>, not a CIXMLData wrapper."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{}]))  # type: ignore[arg-type]

        client.config_item_search("host-1")

        payload = client.http.calls[0]["payload"]
        self.assertEqual({"Equals": "host-1"}, payload["DynamicField_GreenboneHostID"])
        self.assertNotIn("CIXMLData", payload)

    def test_ticket_update_rejects_unrecognized_success_response(self) -> None:
        """TicketUpdate must not treat arbitrary 200 JSON as a successful OTOBO update."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp(
                [
                    {"TicketID": ["42"]},
                    {"Ticket": {"State": "open"}},
                    {},
                ]
            ),
        )  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "TicketUpdate 42 response is missing"):
            workflow.sync_ticket(client, config, sample_finding(), "ci-1")

    def test_sync_ticket_creates_ticket_without_link_when_config_item_is_missing(self) -> None:
        """Findings are still ticketed while scans are waiting for host assets to appear."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{}, {"TicketID": ["43"]}]))  # type: ignore[arg-type]

        workflow.sync_ticket(client, config, sample_finding(), None)

        create_payload = client.http.calls[1]["payload"]
        self.assertNotIn("Link", create_payload)
        self.assertEqual("1.2.3|192.0.2.10|80/tcp", create_payload["DynamicField"][0]["Value"])

    def test_sync_ticket_updates_existing_ticket_with_link_when_config_item_exists_now(self) -> None:
        """A later run should attach the CMDB link once the host asset can be matched."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp([{"TicketID": ["42"]}, {"Ticket": {"State": "open"}}, {"Success": True}]),
        )  # type: ignore[arg-type]

        workflow.sync_ticket(client, config, sample_finding(), "ci-1")

        update_payload = client.http.calls[2]["payload"]
        self.assertEqual([otobo.config_item_link("ci-1")], update_payload["Link"])

    def test_sync_ticket_updates_existing_ticket_without_link_when_config_item_is_still_missing(self) -> None:
        """Unmatched findings still get an update article even when no CMDB link is possible yet."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp([{"TicketID": ["42"]}, {"Ticket": {"State": "open"}}, {"Success": True}]),
        )  # type: ignore[arg-type]

        workflow.sync_ticket(client, config, sample_finding(), None)

        update_payload = client.http.calls[2]["payload"]
        self.assertIn("Article", update_payload)
        self.assertNotIn("Link", update_payload)

    def test_sync_findings_warns_and_counts_findings_without_config_item_match(self) -> None:
        """Missing host assets are expected during active scans and should not stop ticket sync."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{}, {"TicketID": ["43"]}]))  # type: ignore[arg-type]
        stderr = io.StringIO()

        with mock.patch("sys.stderr", new=stderr):
            unlinked = workflow.sync_findings(client, config, [sample_finding()], {})

        self.assertEqual(1, unlinked)
        self.assertIn("without a CMDB link", stderr.getvalue())
        self.assertNotIn("Link", client.http.calls[1]["payload"])

    def test_config_item_upsert_rejects_unrecognized_success_response(self) -> None:
        """ConfigItemUpsert must expose the config item identifier needed for finding links."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(config, FakeHttp([{"ConfigItemID": ["ci-1"]}, {}]))  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "ConfigItemUpsert host host-1 response is missing"):
            workflow.sync_cmdb_hosts(client, [{"id": "host-1", "name": "web-1"}])

    def test_sync_cmdb_hosts_upserts_existing_config_item_with_id(self) -> None:
        """Existing host CIs are updated by passing ConfigItemID to ConfigItemUpsert."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp([{"ConfigItemID": ["ci-1"]}, {"ConfigItem": [{"ConfigItemID": "ci-1"}]}]),
        )  # type: ignore[arg-type]

        synced = workflow.sync_cmdb_hosts(client, [{"id": "host-1", "name": "web-1", "ip": "192.0.2.10"}])

        self.assertEqual("ci-1", synced[0].id)
        upsert_call = client.http.calls[1]
        self.assertTrue(upsert_call["url"].endswith("/ConfigItemUpsert"))
        self.assertEqual("ci-1", upsert_call["payload"]["ConfigItem"]["ConfigItemID"])
        self.assertEqual("Production", upsert_call["payload"]["ConfigItem"]["DeploymentState"])
        self.assertEqual("Operational", upsert_call["payload"]["ConfigItem"]["IncidentState"])
        self.assertEqual("web-1", upsert_call["payload"]["ConfigItem"]["Name"])
        self.assertEqual("host-1", upsert_call["payload"]["ConfigItem"]["DynamicField_GreenboneHostID"])
        self.assertNotIn("DynamicField_Computer-NICIPAddress", upsert_call["payload"]["ConfigItem"])
        self.assertNotIn("DynamicField_Name", upsert_call["payload"]["ConfigItem"])
        self.assertNotIn("DynamicField_GreenboneSeverity", upsert_call["payload"]["ConfigItem"])

    def test_sync_cmdb_hosts_upserts_new_config_item_without_id(self) -> None:
        """Missing host CIs are created by ConfigItemUpsert without a ConfigItemID."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp([{}, {"ConfigItem": [{"ConfigItemID": "ci-2"}]}]),
        )  # type: ignore[arg-type]

        synced = workflow.sync_cmdb_hosts(client, [{"id": "host-2", "name": "web-2"}])

        self.assertEqual("ci-2", synced[0].id)
        self.assertNotIn("ConfigItemID", client.http.calls[1]["payload"]["ConfigItem"])

    def test_config_item_payload_uses_optional_ip_mapping_when_configured(self) -> None:
        """Deployments with a top-level IP dynamic field can opt into syncing host IPs."""
        config = utils.Config.load(write_env(self, base_env(OTOBO_CONFIG_ITEM_IP_ATTRIBUTE="GreenboneIPAddress")))
        client = otobo.OtoboClient(config, FakeHttp([]))  # type: ignore[arg-type]

        payload = client.config_item_payload({"id": "host-1", "name": "web-1", "ip": "192.0.2.10"})

        self.assertEqual("192.0.2.10", payload["ConfigItem"]["DynamicField_GreenboneIPAddress"])

    def test_sync_ticket_reopens_when_ticket_get_exposes_closed_state(self) -> None:
        """Closed OTOBO tickets are reopened using the configured reopen state."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp(
                [
                    {"TicketID": ["42"]},
                    {"Ticket": {"State": "closed successful"}},
                    {"Success": True},
                ]
            ),
        )  # type: ignore[arg-type]

        workflow.sync_ticket(client, config, sample_finding(), "ci-1")

        update_payload = client.http.calls[2]["payload"]
        self.assertEqual({"State": "open"}, update_payload["Ticket"])
        self.assertEqual([otobo.config_item_link("ci-1")], update_payload["Link"])

    def test_sync_ticket_fails_when_ticket_get_omits_state(self) -> None:
        """Without a ticket state, the example cannot decide whether reopening is required."""
        config = utils.Config.load(write_env(self, base_env()))
        client = otobo.OtoboClient(
            config,
            FakeHttp(
                [
                    {"TicketID": ["42"]},
                    {"Ticket": {"TicketID": "42"}},
                ]
            ),
        )  # type: ignore[arg-type]

        with self.assertRaisesRegex(utils.IntegrationError, "TicketGet Generic Interface operation returns the State"):
            workflow.sync_ticket(client, config, sample_finding(), "ci-1")


class MappingTests(IsolatedEnvTest):
    def test_aggregate_findings_groups_by_oid_host_and_opaque_port(self) -> None:
        """Stable finding keys must reidentify repeated observations without parsing ports."""
        report_a = {"id": "report-a", "scanStart": "2026-07-01T10:00:00Z"}
        report_b = {"id": "report-b", "scanStart": "2026-07-01T11:00:00Z"}
        result = {
            "id": "result-a",
            "host": "192.0.2.10",
            "port": "80/tcp",
            "severity": 7.0,
            "nvt": {"oid": "1.2.3", "name": "Example NVT"},
        }

        findings = workflow.aggregate_findings([(report_a, result), (report_b, {**result, "id": "result-b"})])

        self.assertEqual(1, len(findings))
        self.assertEqual("1.2.3|192.0.2.10|80/tcp", findings[0].key)
        self.assertEqual("2026-07-01T11:00:00Z", utils.format_rfc3339(findings[0].latest_seen))
        self.assertEqual(2, len(findings[0].evidence))

    def test_aggregate_findings_fails_when_required_nvt_oid_is_missing(self) -> None:
        """Missing stable-key fields would break ticket correlation and must stop the run."""
        report = {"id": "report-a", "scanStart": "2026-07-01T10:00:00Z"}
        result = {"id": "result-a", "host": "192.0.2.10", "port": "80/tcp", "severity": 7.0, "nvt": {}}

        with self.assertRaisesRegex(utils.IntegrationError, "oid"):
            workflow.aggregate_findings([(report, result)])

    def test_host_lookup_rejects_ambiguous_inventory_values(self) -> None:
        """A finding host value must not map to multiple CMDB config items."""
        synced_hosts = [
            workflow.SyncedConfigItem(id="ci-1", host={"id": "host-1", "ip": "192.0.2.10"}),
            workflow.SyncedConfigItem(id="ci-2", host={"id": "host-2", "ip": "192.0.2.10"}),
        ]

        with self.assertRaisesRegex(utils.IntegrationError, "multiple OTOBO config items"):
            workflow.build_host_lookup(synced_hosts)

    def test_article_body_includes_optional_fields_for_each_grouped_result(self) -> None:
        """Every grouped result contributes its evidence, not just the first observation."""
        finding = sample_finding()
        finding.evidence.append(
            workflow.Evidence(
                report_id="report-b",
                scan_start=datetime(2026, 7, 1, 11, 30, 0, tzinfo=timezone.utc),
                result={
                    "id": "result-b",
                    "name": "Second NVT name",
                    "host": "192.0.2.10",
                    "port": "80/tcp",
                    "severity": 8.0,
                    "description": "Second description",
                    "nvt": {"oid": "1.2.3", "name": "Second NVT name", "cves": ["CVE-2026-0002"]},
                },
            )
        )

        article = otobo.format_article_body(finding)

        self.assertIn("Result ID: result-a", article)
        self.assertIn("CVEs: CVE-2026-0001", article)
        self.assertIn("Example description", article)
        self.assertIn("Result ID: result-b", article)
        self.assertIn("CVEs: CVE-2026-0002", article)
        self.assertIn("Second description", article)


if __name__ == "__main__":
    unittest.main()
