# Jira Cloud Integration Example Spec

## Purpose

Build a Python 3 example that demonstrates:

- Creating and updating Jira Cloud issues from GVM report results fetched
  through the GVM REST API.
- Reidentifying findings across runs with a stable finding key.
- Using the Python Jira SDK for Jira Cloud issue operations, without Jira
  Assets, CMDB, or another inventory integration.
- Using the gateway API in a small, readable integration script.

This example is not intended to be production-ready.

## Documentation Basis

The Jira Cloud side of this spec is based on Atlassian's Jira Cloud platform
REST API v3 documentation and the Python Jira SDK documentation:

- REST API v3 base paths and authentication models:
  <https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/#about>
- Basic authentication for ad-hoc REST API scripts:
  <https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/>
- Issue search:
  <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/>
- Issues, issue metadata, issue editing, and transitions:
  <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/>
- Issue fields:
  <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-fields/>
- Python Jira SDK examples and API documentation:
  <https://jira.readthedocs.io/>

The example uses Basic authentication because it is an ad-hoc script example.
Production or distributed integrations should use an Atlassian-supported app or
OAuth model instead of asking users to provide personal API tokens.

## Configuration

Configure the example with a `.env` file in
`docs/user/examples/jiracloud/`. Provide a checked-in `.env.example` file that
documents all required settings. The real `.env` file must not be committed.

The `.env` file contains:

- GVM REST API base URL and Basic authentication credentials.
- Jira Cloud site URL, Atlassian account email address, and API token.
- Jira target project key.
- Jira issue type name or ID. Default the README and `.env.example` to `Task`.
- Jira custom field name for the finding key. Default `JIRA_FINDING_KEY_FIELD`
  to `GreenboneFindingKey`.
- Jira labels that should be applied to every issue.
- Optional Jira priority name or severity-to-priority mapping.
- Jira status names or status categories treated as closed.
- Jira transition name used to reopen closed issues.
- GVM report selection window and minimum severity threshold.

## GVM Data Flow

Use the versioned GVM REST API base path `/api/v1`.

1. Create a GVM session with `POST /api/v1/session` using HTTP Basic
   credentials.
2. Use the returned `sessionToken` as `Authorization: Bearer <sessionToken>` for
   all subsequent GVM requests.
3. Fetch reports with `GET /api/v1/reports`.
   - Select reports whose public `scanStart` is within the configured lookback
     window. The default is the last 24 hours.
   - Compute a UTC cutoff timestamp at runtime: `now_utc - lookback`.
   - Use the report filter `scan_start>{cutoff_utc}`, where `{cutoff_utc}` is
     an RFC 3339 timestamp, for example `scan_start>2026-07-01T10:00:00Z`.
   - Request shape:
     `GET /api/v1/reports?filter=scan_start>{cutoff_utc}&perPage=1000`.
   - Read all pages.
   - After fetching reports, still check each returned report's `scanStart`
     client-side and ignore reports outside the configured window.
4. For each selected report, fetch results with
   `GET /api/v1/reports/{id}/results`.
   - Read all pages.
   - Keep only results with `severity > JIRA_MIN_SEVERITY`.
   - Default `JIRA_MIN_SEVERITY` to `4.0`, matching the OTOBO example.
   - Ignore findings with severity less than or equal to `4.0`.
5. Close the GVM session with `DELETE /api/v1/session` when the run finishes.

Use `GET /api/v1/reports/{id}/results` as the finding source. Do not use the
global `GET /api/v1/results` endpoint for this example. Do not use
`GET /api/v1/reports/{id}/vulnerabilities`, because the OpenAPI spec allows it
to return `501 Not Implemented`.

Do not fetch `GET /api/v1/hosts` in this example. Jira Cloud issue creation does
not need host inventory synchronization when there is no CMDB or Jira Assets
integration.

## Finding Aggregation

Aggregate severity-eligible results into findings before writing to Jira.

- Stable finding key: `nvt_oid + result.host + result.port`.
- Source fields:
  - `nvt_oid` comes from `result.nvt.oid`.
  - Host comes from `result.host`.
  - Port comes from `result.port`.
- Treat `result.port` as an opaque key component. Do not parse, split, or
  normalize it to derive protocol information.
- Group all results with the same stable key into one finding.
- Keep all grouped result evidence for the Jira issue description or comment.
- Use the newest associated report `scanStart` as the finding's latest-seen
  timestamp.
- If a severity-eligible result is missing `nvt.oid`, `host`, or `port`, print
  an actionable error and stop the script.
- If optional descriptive fields such as CVEs or description are missing,
  continue and omit those fields from the Jira issue content.

## Jira Cloud SDK

Use the Python Jira SDK package `jira` for Jira Cloud operations. Initialize the
SDK client from:

- `JIRA_SITE_URL`
- `JIRA_EMAIL`
- `JIRA_API_TOKEN`

For example:

```python
JIRA(server=config.jira_site_url, basic_auth=(config.jira_email, config.jira_api_token))
```

The SDK sends Jira Cloud requests through Jira's REST APIs. The example should
use SDK methods rather than hand-built Jira HTTP requests for normal Jira
operations:

- Authentication: `JIRA(..., basic_auth=(email, api_token))`.
- Current user check: `jira.myself()`.
- Field discovery: `jira.fields()`.
- Custom field search when `jira.fields()` does not expose the configured
  field: the SDK-managed `_get_json("field/search", ...)` path for Jira Cloud.
- Issue type and create metadata checks: `jira.createmeta(...)`.
- Issue lookup: `jira.search_issues(...)`.
- Issue creation: `jira.create_issue(...)`.
- Issue update: `issue.update(...)`.
- Issue comments: `jira.add_comment(...)`.
- Transitions: `jira.transitions(...)` and `jira.transition_issue(...)`.

Use plain text strings for Jira issue descriptions and comments. The Python
Jira SDK posts issue creation and comments through its configured REST API
version, and the current SDK defaults to string bodies for these fields.

Do not use Jira Automation rules as the integration mechanism. Do not implement
a local Jira REST client for operations covered by the SDK. Target current Jira
Cloud only; do not add fallbacks for Jira Server, Jira Data Center, or older
Jira Cloud metadata helpers.

## Jira Finding Identity

Represent each Greenbone finding as one Jira issue in the configured project.

Use a Jira custom field for finding identity:

- Custom field name: `GreenboneFindingKey`.
- Field type: single-line text.
- Field value: the full stable finding key.

The README must document that the Jira administrator has to create this custom
field before the synchronization script is run and add it to the create/edit
screens for the configured project and issue type. The script verifies the
field and resolves its Jira field ID, for example `customfield_10042`, during
preflight. The synchronization run must not create or modify Jira
administrative configuration because custom-field creation and screen
configuration require Jira configuration privileges and are a different
operational concern from finding synchronization.

Search for existing issues with:

```text
jira.search_issues(...)
```

Use JQL shaped like:

```text
project = "<JIRA_PROJECT_KEY>" AND "<JIRA_FINDING_KEY_FIELD>" = "<stable_finding_key>" ORDER BY updated DESC
```

Request only the fields needed by the script, such as `key`, `status`, `labels`,
`summary`, the configured finding-key custom field, and optionally `priority`.

If no issue matches the finding key, create a new issue. If exactly one issue
matches, update that issue. If more than one issue matches, stop with an
actionable error instead of choosing an arbitrary issue.

Labels may still be applied for Jira filtering and reporting, but labels are
not the authoritative finding identity.

## Jira Preflight

Before synchronizing findings, run Jira preflight checks. The example checks
required Jira setup but does not create or modify Jira administrative
configuration.

Implement preflight checks with the same Jira credentials and SDK client used
by issue synchronization:

- Call `jira.myself()` to verify authentication.
- Call `jira.fields()` and verify that the configured
  `GreenboneFindingKey` custom field is visible. Fail if no matching field
  exists or if multiple fields have the configured name.
- Call `jira.createmeta(...)` to query issue types and verify that the
  configured issue type exists. Default to `Task`.
- Call `jira.createmeta(...)` to verify that the create screen accepts the
  fields the script will set, especially `summary`, `description`, `labels`,
  and the resolved finding-key custom field ID.
- Call `jira.search_issues(...)` with a narrow harmless query for the
  configured project to verify browse permission and JQL access.

Do not attempt to create Jira custom fields, modify screens, modify workflows,
or create projects from the synchronization script. The README may show the
administrator-facing REST operation `POST /rest/api/3/field` as one possible
way to create the custom field, but that setup step is separate from normal
synchronization.

## Jira Issues

For each finding:

1. Search for an existing Jira issue by the configured finding-key custom
   field.
2. If no issue exists, create an issue with `jira.create_issue(...)`.
   - Set `project` to the configured project key or ID.
   - Set `issuetype` to `Task` by default, or to the configured issue type name
     or ID when overridden.
   - Set `summary` to a concise finding title that includes the NVT name, host,
     and port when available.
   - Set `description` to plain text containing the current scan evidence.
   - Set the resolved finding-key custom field ID to the stable finding key.
   - Set `labels` to any configured static labels.
   - Set `priority` only when configured and accepted by the project screen.
3. If an issue exists, update it.
   - Add a new comment with `jira.add_comment(...)` containing the current
     scan evidence as plain text.
   - Ensure the configured static labels are still present with
     `issue.update(...)` when they were removed.
   - Ensure the resolved finding-key custom field still equals the stable
     finding key.
   - If the issue is closed, fetch available transitions with
     `jira.transitions(...)`, select `JIRA_REOPEN_TRANSITION_NAME` by exact
     name, and call `jira.transition_issue(...)`.
   - If the issue is closed and no matching reopen transition is available,
     print an actionable error and stop the script with a non-zero exit code.

Do not close Jira issues when a finding is absent from the selected report
window. This example only creates issues, updates issues, comments on recurring
findings, and reopens closed issues when the finding is seen again.

## Jira Issue Content

Create issue descriptions and update comments with compact plain text that
contains:

- Stable finding key.
- NVT name and OID.
- Severity and threat.
- Host and opaque port value.
- Latest-seen timestamp.
- Report IDs and scan start timestamps for grouped evidence.
- Result IDs for grouped evidence.
- CVEs when present.
- Description text when present.

Keep generated Jira content concise. If grouped evidence is large, include a
bounded number of result rows and print a warning that the Jira issue content
was truncated.

## Error Handling

This is an example script, not a production-ready integration. If any required
configuration, preflight check, GVM API request, Jira SDK operation, or data
mapping step fails:

1. Print a clear, actionable error message.
2. Stop the script with a non-zero exit code.

Do not implement retries, background recovery, partial sync continuation, or
local compensation logic. Jira Cloud may rate-limit clients; let the SDK surface
the failure and print an actionable message, but do not add custom retry and
backoff behavior in this example.

## Tech Stack

- Python 3
- uv
- Direct HTTP client calls to the GVM REST API
- Python Jira SDK package `jira` for Jira Cloud operations
