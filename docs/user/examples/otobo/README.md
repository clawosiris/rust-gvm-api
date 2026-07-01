# OTOBO Integration Example

This Python 3 example synchronizes recent Greenbone scan findings into OTOBO:

- GVM hosts are synchronized to OTOBO CMDB config items.
- Results from reports started in the last 24 hours are aggregated into stable
  findings.
- Each finding creates or updates one OTOBO ticket through the OTOBO Generic
  Interface.

The example is intentionally small and fail-fast. It is not production-ready
and does not implement retries, background recovery, partial continuation, or
local compensation logic.

## Run

Copy the example configuration and adjust it for your GVM REST API and OTOBO
instance:

```sh
cp .env.example .env
uv run python main.py
```

The script uses only the Python standard library. The `.env` file contains
credentials and must not be committed.

## Configuration

`GVM_API_URL` must include the versioned REST API base path:

```text
http://localhost:8080/api/v1
```

OTOBO operation path names are configurable because Generic Interface routes
are chosen by the OTOBO administrator. The script builds OTOBO URLs from:

```text
OTOBO_BASE_URL / OTOBO_WEB_SERVICE / OTOBO_OPERATION_*
```

Every OTOBO request sends `UserLogin` and `Password` in the JSON payload. The
example does not create an OTOBO session.

## OTOBO Prerequisites

Create one ticket Dynamic Field before running the example. The example uses
this field to correlate Greenbone findings with existing OTOBO tickets.

1. Sign in to OTOBO as an administrator.
2. Open the admin area and go to the Dynamic Fields configuration.
3. Create a new ticket Dynamic Field with these settings:
   - Object type: `Ticket`
   - Field type: `Text`
   - Name: `GreenboneFindingKey`
   - Label: `Greenbone Finding Key`
4. Save the field and make sure it is active.
5. Include `GreenboneFindingKey` in the OTOBO Generic Interface web service
   operations used by this example, especially `TicketSearch`, `TicketGet`,
   `TicketCreate`, and `TicketUpdate`.

Install and configure the OTOBO ITSM Configuration Management / CMDB add-on.
The configured Generic Interface operations must allow:

- `ConfigItemSearch`
- `ConfigItemCreate`
- `ConfigItemUpdate`

The configured CMDB class must expose attributes matching these `.env`
settings:

- `OTOBO_CONFIG_ITEM_EXTERNAL_KEY_ATTRIBUTE`
- `OTOBO_CONFIG_ITEM_NAME_ATTRIBUTE`
- `OTOBO_CONFIG_ITEM_IP_ATTRIBUTE`
- `OTOBO_CONFIG_ITEM_HOSTNAME_ATTRIBUTE`
- `OTOBO_CONFIG_ITEM_OS_ATTRIBUTE`
- `OTOBO_CONFIG_ITEM_SEVERITY_ATTRIBUTE`

The script verifies the ticket Dynamic Field and CMDB search setup during
preflight. It does not create or modify OTOBO administrative configuration.
For the harmless no-match preflight searches, the script accepts empty
recognized search result fields such as `TicketID: []` for `TicketSearch` and
`ConfigItemID: []` for `ConfigItemSearch`. If a valid OTOBO setup uses
different no-match field names, adjust the example's accepted response shapes
or the Generic Interface operation mapping before using it.

## GVM Data Flow

The example uses the GVM session flow:

1. `POST /api/v1/session` with HTTP Basic credentials.
2. Subsequent GVM requests use `Authorization: Bearer <sessionToken>`.
3. `GET /api/v1/hosts` reads all pages for CMDB synchronization.
4. `GET /api/v1/reports` reads all pages with a report filter for scans started
   in the last 24 hours.
5. `GET /api/v1/reports/{id}/results` reads all pages for each selected report.
6. `DELETE /api/v1/session` closes the session when the run finishes.

The report filter has this shape:

```text
scan_start>{cutoff_utc}
```

For example:

```text
GET /api/v1/reports?filter=scan_start>2026-07-01T10:00:00Z&perPage=1000
```

The script still checks every returned report's public `scanStart` value
client-side and ignores reports outside the 24-hour window.

## Finding Correlation

Only report results with `severity > 4.0` are synchronized. Results are grouped
into findings by this stable key:

```text
nvt_oid|result.host|result.port
```

`result.port` is treated as an opaque value. The script does not parse it to
derive protocol information.

If a severity-eligible result is missing `nvt.oid`, `host`, or `port`, the
script exits with an error. Optional fields such as CVEs and descriptions are
included in ticket articles when available and omitted when absent.

## Error Handling

The example stops on the first unrecoverable failure. Configuration errors,
preflight failures, GVM request failures, OTOBO request failures, ambiguous
CMDB host lookup values, and missing finding key fields all produce a clear
message on stderr and a non-zero exit code.
