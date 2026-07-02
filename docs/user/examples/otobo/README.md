# OTOBO Integration Example

This Python 3 example synchronizes recent Greenbone scan findings into OTOBO.
It syncs GVM hosts to OTOBO CMDB config items, groups report results into stable
findings, and creates or updates one OTOBO ticket per finding.

The example is intentionally small and fail-fast. It does not implement retries,
background recovery, or production sync state.

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
- OTOBO access: `OTOBO_BASE_URL`, `OTOBO_WEB_SERVICE`, `OTOBO_USERNAME`,
  `OTOBO_PASSWORD`.
- OTOBO routes: all `OTOBO_OPERATION_*` values.
- Ticket defaults: queue, customer user, states, priority, article sender type,
  and article type.
- CMDB mapping: class, deployment state, incident state, and config item
  attribute names.

`GVM_GATEWAY_BASE_URL` is the gateway root URL without `/api/v1`, for example:

```text
GVM_GATEWAY_BASE_URL=http://127.0.0.1:8080
```

The script appends `/api/v1` internally.

## 2. Prepare GVM Access

The GVM user configured in `.env` must be able to create sessions and read the
data being synchronized:

- `POST /api/v1/session`
- `DELETE /api/v1/session`
- `GET /api/v1/hosts`
- `GET /api/v1/reports`
- `GET /api/v1/reports/{id}/results`

The script fetches reports visible to that GVM user. It does not bypass GVM
permissions.

## 3. Prepare OTOBO Ticket Data

Create a ticket Dynamic Field:

- Object type: `Ticket`
- Field type: `Text`
- Name: `GreenboneFindingKey`
- Label: `Greenbone Finding Key`

Set `OTOBO_FINDING_KEY_FIELD=GreenboneFindingKey`.

The ticket defaults in `.env` must name existing OTOBO values:

- `OTOBO_TICKET_QUEUE`
- `OTOBO_TICKET_CUSTOMER_USER`
- `OTOBO_TICKET_STATE_NEW`
- `OTOBO_TICKET_PRIORITY`
- `OTOBO_TICKET_ARTICLE_SENDER_TYPE`
- `OTOBO_TICKET_ARTICLE_TYPE`
- `OTOBO_CLOSED_STATES`
- `OTOBO_REOPEN_STATE`

`OTOBO_TICKET_CUSTOMER_USER` must be an existing OTOBO customer user. Otherwise
`TicketCreate` is rejected by OTOBO.

## 4. Prepare OTOBO CMDB

Install and enable the OTOBO ITSM Configuration Management / CMDB add-on. The
default `.env.example` uses the `Computer` config item class.

For the default mapping:

- Use `OTOBO_CONFIG_ITEM_CLASS=Computer`.
- Use `OTOBO_CONFIG_ITEM_NAME_ATTRIBUTE=Name`.
- Use `OTOBO_CONFIG_ITEM_HOSTNAME_ATTRIBUTE=Computer-FQDN`.
- Use `OTOBO_CONFIG_ITEM_OS_ATTRIBUTE=Computer-OperatingSystem`.
- Create a top-level ITSM config item Dynamic Field named `GreenboneHostID`.
- Add `GreenboneHostID` to the `Computer` class definition.
- Set `OTOBO_CONFIG_ITEM_EXTERNAL_KEY_ATTRIBUTE=GreenboneHostID`.

`Name` is a built-in config item field. Other CMDB mappings are Dynamic Field
names without the `DynamicField_` prefix; the script adds that prefix when it
calls OTOBO.

`OTOBO_CONFIG_ITEM_IP_ATTRIBUTE` is optional. Only set it when your class has a
top-level IP address Dynamic Field. The imported `Computer` class stores IPs in
the nested `Computer-NIC` set, so do not use `Computer-NICIPAddress` as a
top-level mapping.

## 5. Configure OTOBO Generic Interface

Create an OTOBO Generic Interface web service with HTTP::REST provider routes.
The script builds each OTOBO URL like this:

```text
OTOBO_BASE_URL / OTOBO_WEB_SERVICE / OTOBO_OPERATION_*
```

With the default `.env.example`, the route mapping must include these `POST`
routes:

| Route | Provider operation |
| --- | --- |
| `/TicketSearch` | `Ticket::TicketSearch` |
| `/TicketGet` | `Ticket::TicketGet` |
| `/TicketCreate` | `Ticket::TicketCreate` |
| `/TicketUpdate` | `Ticket::TicketUpdate` |
| `/ConfigItemSearch` | `ConfigItem::ConfigItemSearch` |
| `/ConfigItemUpsert` | `ConfigItem::ConfigItemUpsert` |

The operations must allow the fields used by the script:

- `TicketSearch`: search by `DynamicField_GreenboneFindingKey`.
- `TicketGet`: return the ticket state.
- `TicketCreate` and `TicketUpdate`: accept `GreenboneFindingKey` and CMDB
  links.
- `ConfigItemSearch`: search by `DynamicField_GreenboneHostID`.
- `ConfigItemUpsert`: accept `Class`, `DeploymentState`, `IncidentState`,
  built-in `Name`, and the configured top-level CMDB Dynamic Fields.

Use an OTOBO user that can search, create, and update tickets and config items.
The script sends that user as `UserLogin` and `Password` in every OTOBO request.

## 6. Run

Run from this directory:

```sh
uv run python main.py
```

Successful output looks like this:

```text
Synchronization complete: <host-count> host(s), <report-count> report(s), <finding-count> finding(s), <unlinked-count> without CMDB link.
```

## What Gets Synchronized

The script reads reports started in the last 24 hours:

```text
GET /api/v1/reports?filter=scan_start>{cutoff_utc}&perPage=1000
```

It reads all pages, fetches results for each selected report, and keeps only
results with `severity > 4.0`.

Findings are grouped by:

```text
nvt_oid|result.host|result.port
```

`result.port` is treated as an opaque value. If a severity-eligible result is
missing `nvt.oid`, `host`, or `port`, the script stops with an error.

If a finding host is not available in `GET /api/v1/hosts` yet, the ticket is
created or updated without a CMDB link. A later run adds the link once the host
asset appears.

## Troubleshooting

- `RouteOperationMapping`: check the HTTP::REST route names and provider
  operations in the OTOBO web service.
- `Ticket->CustomerUser parameter is invalid`: fix
  `OTOBO_TICKET_CUSTOMER_USER`.
- `DynamicField->Name parameter is invalid`: remove invalid CMDB Dynamic Field
  mappings, especially nested fields such as `Computer-NICIPAddress`.
- Missing ticket state: make `TicketGet` return `State`.
- Empty search responses: valid no-match searches may return `{}` or empty ID
  lists. Other shapes usually mean the operation mapping needs adjustment.

## Error Handling

The example stops on the first unrecoverable configuration, GVM, OTOBO, or data
mapping error and prints the failing operation plus response details when
available.
