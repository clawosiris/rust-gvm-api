# OTOBO Integration Example Spec

## Purpose

Build a Python 3 example that demonstrates:

- Creating and updating OTOBO tickets from GVM report results fetched through
  the GVM REST API.
- Reidentifying findings across runs with a stable finding key.
- Synchronizing discovered GVM hosts to OTOBO CMDB config items.
- Using the gateway API in a small, readable integration script.

This example is not intended to be production-ready.

## Configuration

Configure the example with a `.env` file in `docs/user/examples/otobo/`.
Provide a checked-in `.env.example` file that documents all required settings.
The real `.env` file must not be committed.

The `.env` file contains:

- GVM REST API base URL and Basic authentication credentials.
- OTOBO Generic Interface base URL, web service name, and authentication
  credentials.
- OTOBO Generic Interface operation path names.
- OTOBO ticket defaults required by ticket creation and updates.
- OTOBO state names used to identify closed tickets and reopen them.
- OTOBO CMDB config item class, deployment state, incident state, and attribute
  mapping settings.

## GVM Data Flow

Use the versioned GVM REST API base path `/api/v1`.

1. Create a GVM session with `POST /api/v1/session` using HTTP Basic
   credentials.
2. Use the returned `sessionToken` as `Authorization: Bearer <sessionToken>` for
   all subsequent GVM requests.
3. Fetch discovered hosts/assets with `GET /api/v1/hosts`.
   - Use host `id`, `name`, `hostname`, and `os` for OTOBO CMDB
     synchronization.
   - Optionally use host `ip` when the configured OTOBO CMDB class exposes a
     top-level IP address Dynamic Field.
   - Read all pages.
4. Fetch reports with `GET /api/v1/reports`.
   - Select reports whose public `scanStart` is within the last 24 hours.
   - Compute a UTC cutoff timestamp at runtime: `now_utc - 24 hours`.
   - Use the report filter `scan_start>{cutoff_utc}`, where `{cutoff_utc}` is
     an RFC 3339 timestamp, for example `scan_start>2026-07-01T10:00:00Z`.
   - Request shape: `GET /api/v1/reports?filter=scan_start>{cutoff_utc}&perPage=1000`.
   - Read all pages.
   - After fetching reports, still check each returned report's `scanStart`
     client-side and ignore reports outside the 24-hour window.
5. For each selected report, fetch results with
   `GET /api/v1/reports/{id}/results`.
   - Read all pages.
   - Keep only results with `severity > 4.0`.
6. Close the GVM session with `DELETE /api/v1/session` when the run finishes.

Use `GET /api/v1/reports/{id}/results` as the finding source. Do not use the
global `GET /api/v1/results` endpoint for this example. Do not use
`GET /api/v1/reports/{id}/vulnerabilities`, because the OpenAPI spec allows it
to return `501 Not Implemented`.

## Finding Aggregation

Aggregate severity-eligible results into findings before writing to OTOBO.

- Stable finding key: `nvt_oid + result.host + result.port`.
- Source fields:
  - `nvt_oid` comes from `result.nvt.oid`.
  - Host comes from `result.host`.
  - Port comes from `result.port`.
- Treat `result.port` as an opaque key component. Do not parse, split, or
  normalize it to derive protocol information.
- Group all results with the same stable key into one finding.
- Keep all grouped result evidence for the OTOBO ticket article.
- Use the newest associated report `scanStart` as the finding's latest-seen
  timestamp.
- If a severity-eligible result is missing `nvt.oid`, `host`, or `port`, print
  an actionable error and stop the script.
- If optional descriptive fields such as CVEs or description are missing,
  continue and omit those fields from the ticket article.

## OTOBO Generic Interface

Use OTOBO Generic Interface as a REST provider with HTTP::REST. The endpoint
pattern is:

```text
/otobo/nph-genericinterface.pl/Webservice/<WEB_SERVICE>/<OPERATION>
```

Build OTOBO request URLs from:

- `OTOBO_BASE_URL`
- `OTOBO_WEB_SERVICE`
- the configured operation path name

The `<OPERATION>` path names are configured in `.env`. Provide defaults for:

- `TicketSearch`
- `TicketGet`
- `TicketCreate`
- `TicketUpdate`
- `ConfigItemSearch`
- `ConfigItemUpsert`

Do not hard-code operation path names in the script because OTOBO web service
route names are configured by the administrator.

Use direct per-request credentials in each OTOBO Generic Interface JSON
payload. Include the configured OTOBO username and password as `UserLogin` and
`Password` fields. Do not create an OTOBO session.

Do not use the GVM REST API `/api/v1/tickets` endpoints for OTOBO ticket
operations. Those endpoints are part of the GVM ticket discovery surface, not
the OTOBO Generic Interface.

## OTOBO Preflight

Before synchronizing data, run OTOBO preflight checks. The example checks
required OTOBO setup but does not create or modify OTOBO administrative
configuration.

Implement preflight checks as smoke checks through the same OTOBO Generic
Interface operations used by the synchronization run:

- Run a narrow ticket search using the configured `GreenboneFindingKey` Dynamic
  Field. Fail if OTOBO rejects the field, operation, or credentials.
- Run a harmless config item search using the configured config item class and
  external key attribute. Fail if OTOBO rejects the class, operation, attribute,
  or credentials.

## OTOBO Tickets

The example requires exactly one OTOBO ticket Dynamic Field:
`GreenboneFindingKey`. The README documents how to create it. The script assumes
the field exists and verifies it during preflight.

For each finding:

1. Search for an existing OTOBO ticket by `GreenboneFindingKey`.
2. If no ticket exists, create a ticket:
   - Set `GreenboneFindingKey` to the stable finding key.
   - Use configured ticket defaults from `.env`.
   - Add an article containing the current scan evidence.
   - Link the matching CMDB config item when one is available.
3. If a ticket exists, update it:
   - Always add a new internal article containing the current scan evidence.
   - If the ticket state is in `OTOBO_CLOSED_STATES`, set the ticket state to
     `OTOBO_REOPEN_STATE`.
   - Link the matching CMDB config item when one is available. This lets a
     later run attach the CMDB link after GVM host inventory catches up with
     report results.

## OTOBO CMDB

Install and configure the OTOBO ITSM Configuration Management / CMDB add-on
before running the example.

Sync GVM hosts to OTOBO config items before processing findings:

1. Build an external CI key from the Greenbone host UUID returned by
   `GET /api/v1/hosts`.
2. Search for a config item by the configured class and external key attribute.
3. Upsert the config item with `ConfigItem::ConfigItemUpsert`.
   - If the search found an existing config item, pass its `ConfigItemID` to
     update it.
   - If the search found no existing config item, omit `ConfigItemID` so OTOBO
     creates it.
4. Build a lookup from synchronized CMDB host data so findings can be linked to
   config items by matching each result's `host` value against host inventory
   values used for CMDB sync, especially host `ip`, `name`, and `hostname`.
5. If a finding cannot be matched to a synchronized config item, still create
   or update the OTOBO ticket without a CMDB link and print a warning. This can
   happen while a scan is still completing and report results are visible before
   the matching host asset appears in `GET /api/v1/hosts`.

Config item upsert payloads must include the configured:

- Config item class.
- Deployment state.
- Incident state.
- Version data.

Map GVM host fields into configured OTOBO config item attributes:

- Greenbone host `id` -> configured external key attribute.
- Greenbone host `name` -> configured name attribute.
- Greenbone host `hostname` -> configured hostname attribute.
- Greenbone host `os` -> configured operating system attribute.
- Greenbone host `ip` -> optional configured IP address attribute, when set.

Except for the built-in config item `Name` field, the configured attribute
names are OTOBO ITSM config item Dynamic Field names without the
`DynamicField_` prefix. The script adds that prefix when calling
`ConfigItemSearch` and `ConfigItemUpsert`.

Custom mapped fields, such as the default Greenbone host ID attribute, must
exist as ITSM config item Dynamic Fields and be part of the configured CMDB
class definition.

## Error Handling

This is an example script, not a production-ready integration. If any required
configuration, preflight check, GVM API request, OTOBO API request, or data
mapping step fails:

1. Print a clear, actionable error message.
2. Stop the script with a non-zero exit code.

Do not implement retries, background recovery, partial sync continuation, or
local compensation logic.

## Tech Stack

- Python 3
- uv
