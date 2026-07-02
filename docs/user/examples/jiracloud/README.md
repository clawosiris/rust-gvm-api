# Jira Cloud Integration Example

This Python 3 example synchronizes recent Greenbone scan findings into Jira
Cloud. It groups GVM report results into stable findings and creates or updates
one Jira issue per finding.

The example is intentionally small and fail-fast. It does not implement
retries, production sync state, or automatic remediation closure.

## 1. Create `.env`

The script reads configuration from `.env` in this directory. Start from the
template:

```sh
cp .env.example .env
```

Do not commit `.env`; it contains credentials.

Set these groups of values:

- GVM access: `GVM_GATEWAY_BASE_URL`, `GVM_GATEWAY_USERNAME`,
  `GVM_GATEWAY_PASSWORD`.
- Jira access: `JIRA_SITE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`.
- Jira issue setup: `JIRA_PROJECT_KEY`, `JIRA_ISSUE_TYPE`,
  `JIRA_FINDING_KEY_FIELD`, `JIRA_LABELS`, and optional `JIRA_PRIORITY`.
- Jira lifecycle: `JIRA_CLOSED_STATUS_NAMES`,
  `JIRA_CLOSED_STATUS_CATEGORIES`, and `JIRA_REOPEN_TRANSITION_NAME`.
- GVM report selection: `JIRA_LOOKBACK_HOURS` and `JIRA_MIN_SEVERITY`.

`GVM_GATEWAY_BASE_URL` is the gateway root URL without `/api/v1`, for example:

```text
GVM_GATEWAY_BASE_URL=http://127.0.0.1:8080
```

`JIRA_SITE_URL` is the Jira Cloud site URL without `/rest/api/3`, for example:

```text
JIRA_SITE_URL=https://example.atlassian.net
```

## 2. Prepare GVM Access

The GVM user configured in `.env` must be able to create sessions and read the
data being synchronized:

- `POST /api/v1/session`
- `DELETE /api/v1/session`
- `GET /api/v1/reports`
- `GET /api/v1/reports/{id}/results`

The script fetches reports visible to that GVM user. It does not bypass GVM
permissions.

## 3. Prepare Jira Cloud

Create a Jira custom field:

- Field type: single-line text
- Name: `GreenboneFindingKey`

Set:

```text
JIRA_FINDING_KEY_FIELD=GreenboneFindingKey
```

Add the field to the create and edit screens used by the configured project and
issue type. The default issue type is `Task`.

The Jira user configured in `.env` must be able to:

- Browse the project.
- Create issues.
- Edit issues.
- Add comments.
- Transition closed issues back to an active status.

The script uses the Python Jira SDK with Jira Cloud API token authentication:

```text
JIRA_EMAIL=<atlassian-account-email>
JIRA_API_TOKEN=<api-token>
```

## 4. Run

Run from this directory:

```sh
uv run python main.py
```

Successful output looks like this:

```text
Synchronization complete: <report-count> report(s), <finding-count> finding(s).
```

## What Gets Synchronized

The script reads reports started in the configured lookback window:

```text
GET /api/v1/reports?filter=scan_start>{cutoff_utc}&perPage=1000
```

It reads all pages, fetches results for each selected report, and keeps only
results with `severity > JIRA_MIN_SEVERITY`. The default threshold is `4.0`.

Findings are grouped by:

```text
nvt_oid|result.host|result.port
```

`result.port` is treated as an opaque value. If a severity-eligible result is
missing `nvt.oid`, `host`, or `port`, the script stops with an error.

For each finding, the script searches Jira by the configured
`GreenboneFindingKey` custom field. It creates a `Task` when no issue exists,
adds a comment when the issue already exists, restores configured labels when
needed, and reopens closed issues with `JIRA_REOPEN_TRANSITION_NAME`.

The script does not close Jira issues when a finding disappears from the
selected report window.

## Troubleshooting

- Missing `GreenboneFindingKey`: set `JIRA_FINDING_KEY_FIELD` to the exact Jira
  custom field display name, for example `Greenbone Finding Key`, or to the
  field ID, for example `customfield_10042`.
- Field search finds the field but create metadata rejects it: add the field to
  a context for the configured project and `Task` issue type, then add it to
  the project create and edit screens.
- JQL search fails: verify the configured custom field is searchable and the
  user can browse the project.
- Reopen fails: verify `JIRA_REOPEN_TRANSITION_NAME` exactly matches a
  transition available to the configured Jira user on closed issues.
- GVM authentication fails: verify the gateway URL and GVM credentials.

## Error Handling

The example stops on the first unrecoverable configuration, GVM, Jira, or data
mapping error and prints the failing operation plus response details when
available.
