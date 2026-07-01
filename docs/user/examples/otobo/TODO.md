# OTOBO Example Implementation Plan

This plan implements the behavior specified in `SPEC.md` for the Python 3
OTOBO integration example. It should not change the specification unless that
is requested explicitly.

## 1. Project Skeleton And Dependencies

- [x] Update `pyproject.toml` with the runtime dependencies needed by the
  script:
  - Implemented with the Python standard library, so no external runtime
    dependencies are needed.
  - `pyproject.toml` keeps `dependencies = []`.
- [x] Keep `main.py` as a small readable example script, with helper classes or
  functions only where they make the data flow clearer.
- [x] Make the script executable through `uv run python main.py` from
  `docs/user/examples/otobo/`.

Acceptance criteria:

- The example starts by loading configuration from `.env`.
- Missing dependencies or configuration produce clear, actionable messages.

## 2. Configuration Model

- [x] Define a typed configuration object that reads every setting documented
  in `.env.example`.
- [x] Validate required settings at startup:
  - GVM API URL, username, and password.
  - OTOBO base URL, web service, username, and password.
  - OTOBO Generic Interface operation path names.
  - Ticket defaults and lifecycle state settings.
  - CMDB class, deployment state, incident state, and attribute mapping names.
- [x] Parse `OTOBO_CLOSED_STATES` as a comma-separated list and trim
  whitespace.
- [x] Normalize URL joining only at the URL level. Do not hard-code OTOBO
  operation route names in code.

Acceptance criteria:

- A missing or blank required setting stops the script before any network
  request.
- The real `.env` remains ignored and uncommitted.

## 3. GVM REST API Client

- [x] Implement session lifecycle:
  - `POST /api/v1/session` with HTTP Basic auth.
  - Store `sessionToken` from the `201` response.
  - Use `Authorization: Bearer <sessionToken>` for protected GVM calls.
  - Always attempt `DELETE /api/v1/session` when the run finishes after a
    session was created.
- [x] Implement paginated `GET /api/v1/hosts`.
- [x] Implement report selection:
  - Compute `cutoff_utc = now_utc - 24 hours`.
  - Request `GET /api/v1/reports?filter=scan_start>{cutoff_utc}&perPage=1000`.
  - Read all pages.
  - Recheck each returned report's public `scanStart` client-side.
- [x] Implement paginated `GET /api/v1/reports/{id}/results` for selected
  reports.
- [x] Keep only results with `severity > 4.0`.
- [x] Do not call global `GET /api/v1/results`.
- [x] Do not call `GET /api/v1/reports/{id}/vulnerabilities`.

Acceptance criteria:

- GVM calls use the `/api/v1` base path and the response shapes from
  `spec/rest-api/sessions.yaml`, `supporting-resources.yaml`,
  `reports.yaml`, `results.yaml`, and `common.yaml`.
- Pagination follows the shared `data` plus `pagination` response pattern.
- Any non-success GVM response stops the script with endpoint, status, and
  response detail.

## 4. OTOBO Generic Interface Client

- [x] Build operation URLs from:
  - `OTOBO_BASE_URL`
  - `OTOBO_WEB_SERVICE`
  - The configured operation path name.
- [x] Send direct per-request OTOBO credentials in every JSON payload:
  - `UserLogin`
  - `Password`
- [x] Implement wrappers for configured operations:
  - `TicketSearch`
  - `TicketGet`
  - `TicketCreate`
  - `TicketUpdate`
  - `ConfigItemSearch`
  - `ConfigItemCreate`
  - `ConfigItemUpdate`
- [x] Do not create an OTOBO session.
- [x] Do not use the GVM REST API `/api/v1/tickets` endpoints for OTOBO ticket
  work.

Acceptance criteria:

- Changing operation names in `.env` changes the called OTOBO routes without a
  code change.
- Any rejected OTOBO operation stops the script with the operation name,
  endpoint, and response detail.

## 5. OTOBO Preflight Checks

- [x] Before sync, run a narrow ticket search using the configured
  `GreenboneFindingKey` dynamic field.
- [x] Before sync, run a harmless config item search using:
  - The configured config item class.
  - The configured external key attribute.
- [x] Treat rejected credentials, fields, classes, attributes, or operation
  paths as fatal setup errors.
- [x] Do not create or modify OTOBO administrative configuration.

Acceptance criteria:

- The script fails early with a setup-focused message when OTOBO is missing the
  required Dynamic Field, CMDB class, attribute, operation, or credentials.

## 6. CMDB Host Synchronization

- [x] Convert every GVM host into CMDB version data using configured attribute
  names:
  - `id` -> external key attribute.
  - `name` -> name attribute.
  - `ip` -> IP address attribute.
  - `hostname` -> hostname attribute.
  - `os` -> operating system attribute.
  - `severity` -> Greenbone severity attribute.
- [x] For each host, search by configured class and external key attribute.
- [x] Create missing config items.
- [x] Update existing config items.
- [x] Include configured class, deployment state, incident state, and version
  data in create/update payloads.
- [x] Build an in-memory lookup from synchronized host inventory values to
  config item identifiers:
  - `ip`
  - `name`
  - `hostname`
- [x] Stop if duplicate host lookup keys would make finding-to-CI linking
  ambiguous.

Acceptance criteria:

- CMDB sync runs before finding ticket processing.
- Every finding result host can be matched to a synchronized config item or the
  script stops with the unmatched host value and suggested CMDB mapping checks.

## 7. Finding Aggregation

- [x] Aggregate severity-eligible report results by stable key:
  - `result.nvt.oid`
  - `result.host`
  - `result.port`
- [x] Treat `result.port` as opaque. Do not parse, split, or normalize it.
- [x] Stop with an actionable data error if any eligible result is missing:
  - `nvt.oid`
  - `host`
  - `port`
- [x] Keep all grouped result evidence for ticket articles.
- [x] Use the newest associated report `scanStart` as the finding's
  latest-seen timestamp.
- [x] Continue when optional descriptive fields are missing, including CVEs or
  description.

Acceptance criteria:

- Multiple results with the same stable key produce one finding.
- The article evidence still lists each grouped result clearly.

## 8. Ticket Synchronization

- [x] For each finding, search for an existing OTOBO ticket by the configured
  `GreenboneFindingKey` Dynamic Field.
- [x] If no ticket exists, create one:
  - Set `GreenboneFindingKey`.
  - Apply configured ticket defaults.
  - Add an article containing current scan evidence.
  - Link the matching CMDB config item.
- [x] If a ticket exists, fetch details if needed to inspect its current state.
- [x] For existing tickets, always add a new internal article containing
  current scan evidence.
- [x] Reopen existing tickets whose state is in `OTOBO_CLOSED_STATES` by
  setting `OTOBO_REOPEN_STATE`.
- [x] Stop if ticket search returns multiple tickets for one finding key.

Acceptance criteria:

- New findings create one OTOBO ticket per stable finding key.
- Reobserved findings append evidence instead of creating duplicate tickets.
- Closed tickets are reopened only when the configured state mapping says they
  are closed.

## 9. Article And Payload Formatting

- [x] Produce a readable internal article body that includes:
  - Stable finding key.
  - Latest-seen timestamp.
  - NVT name and OID.
  - Severity and threat when available.
  - Host and opaque port value.
  - CVEs when present.
  - Description when present.
  - Report IDs and result IDs for evidence.
- [x] Keep payload construction centralized enough that required OTOBO
  credentials and defaults are not duplicated inconsistently.
- [x] Avoid production-only features that the spec excludes, such as retries,
  partial continuation, local compensation, or background recovery.

Acceptance criteria:

- Ticket articles provide enough context for an OTOBO agent to understand what
  was observed and where it came from.
- Payload builders remain example-readable.

## 10. Error Handling And Exit Behavior

- [x] Define a small fatal error helper that prints clear messages to stderr and
  exits non-zero.
- [x] Include enough context in errors:
  - Which configuration key is missing.
  - Which endpoint or OTOBO operation failed.
  - Which result or host could not be mapped.
  - Which setup prerequisite appears missing.
- [x] Ensure the GVM session cleanup still runs after fatal sync errors once a
  session has been created.

Acceptance criteria:

- The first unrecoverable issue stops the script.
- Errors are actionable for a user configuring the example.

## 11. Documentation Updates

- [x] Update `README.md` after implementation to match the final script
  behavior.
- [x] Document how to run the example with `uv`.
- [x] Document OTOBO prerequisites:
  - `GreenboneFindingKey` ticket Dynamic Field.
  - Generic Interface operations.
  - CMDB add-on and configured class/attributes.
- [x] Document that the example is not production-ready and intentionally omits
  retries, recovery, and partial sync continuation.

Acceptance criteria:

- A user can configure `.env`, verify OTOBO prerequisites, and run the script
  from the README alone.

## 12. Verification

- [x] Add focused tests if implementation structure makes pure unit tests
  practical. Test intent should be documented in names or nearby comments.
  Candidate behaviors:
  - Required configuration validation.
  - Closed-state parsing.
  - GVM pagination.
  - Report cutoff filtering.
  - Finding key aggregation and missing required field failures.
  - CMDB host lookup construction and ambiguity detection.
  - OTOBO operation URL construction.
- [x] Add lightweight fake-client or monkeypatch tests instead of requiring
  live GVM or OTOBO services.
- [x] Run the example's Python checks if configured.
- [x] From the repository root, run:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Acceptance criteria:

- Tests cover the high-risk data mapping and idempotency logic without needing
  external services.
- Repository formatting and clippy checks pass before the implementation is
  considered complete.

## 13. Review Fixes

- [x] Tighten OTOBO preflight and Generic Interface response validation so
  setup checks fail on rejected fields, operations, credentials, classes, or
  attributes instead of accepting unrecognized 200 responses.
- [x] Fail GVM pagination when a `data` array contains a malformed non-object
  item instead of silently dropping it.
- [x] Remove the unused `OTOBO_TICKET_STATE_OPEN` configuration key so
  reopening is controlled only by `OTOBO_REOPEN_STATE`.
- [x] Add regression tests for the reviewed issues.
- [x] Rerun:
  - `uv run python -m unittest discover -p '*_test.py'`
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`

## 14. Spec Alignment Review - Open Tasks

Review date: 2026-07-01. These tasks close gaps found by reviewing
`main.py`, `main_test.py`, `README.md`, `.env.example`, and the REST specs
against `SPEC.md`.

- [x] Make GVM pagination response validation strict.
  - Finding: `main.py` currently treats missing `pagination` as the end of
    results and casts `pagination.totalPages` with `int(...)`.
  - Spec alignment: `SPEC.md` requires reading all pages for hosts, reports,
    and report results. `spec/rest-api/common.yaml` defines `pagination` with
    required `page`, `perPage`, `total`, and `totalPages`.
  - Tasks:
    - Require `pagination` to be an object for every paginated GVM response.
    - Validate `page`, `perPage`, `total`, and `totalPages` are present and
      numeric.
    - Raise `ExampleError` with endpoint/page context when pagination is
      missing or malformed.
    - Add regression tests for missing pagination and non-numeric
      `totalPages`.

- [x] Fail on reports returned without a usable `scanStart`.
  - Finding: `main.py` silently ignores a report when `scanStart` is missing.
  - Spec alignment: `SPEC.md` requires selecting reports by public `scanStart`,
    computing a 24-hour cutoff, and checking each returned report's
    `scanStart` client-side.
  - Tasks:
    - Treat missing `scanStart` on a returned report as malformed report data
      instead of silently skipping it.
    - Keep the existing behavior of ignoring reports whose parsed `scanStart`
      is outside the cutoff window.
    - Add a regression test for a report item without `scanStart`.

- [x] Require existing ticket state to be available before deciding whether to
  reopen.
  - Finding: `sync_ticket()` treats an unparseable or missing ticket state from
    `TicketGet` as "not closed" and updates only the article.
  - Spec alignment: `SPEC.md` requires reopening a ticket when its state is in
    `OTOBO_CLOSED_STATES`. If the state cannot be read, the script cannot make
    the required lifecycle decision.
  - Tasks:
    - Make `sync_ticket()` fail with an actionable OTOBO setup/response error
      when `TicketGet` does not expose a state.
    - Add tests for supported `TicketGet` response shapes and for a missing
      state failure.
    - Ensure the error message points users to `TicketGet` Generic Interface
      field exposure/configuration.

- [x] Expand OTOBO operation response validation beyond search preflight.
  - Finding: `TicketUpdate` and `ConfigItemUpdate` currently accept any HTTP
    200 JSON object that does not contain a recognized error field.
  - Spec alignment: `SPEC.md` says any OTOBO API request failure must stop the
    script with a clear message.
  - Tasks:
    - Define minimal expected success response shapes for `TicketGet`,
      `TicketCreate`, `TicketUpdate`, `ConfigItemCreate`, and
      `ConfigItemUpdate`.
    - Validate those shapes after each operation and fail with operation name
      plus response detail when unrecognized.
    - Add regression tests for unrecognized 200 responses from update
      operations.

- [x] Preserve complete grouped result evidence in ticket articles.
  - Finding: `format_article_body()` includes full descriptive fields only
    from the first grouped result, while grouped evidence rows include only
    report ID, result ID, scan start, and severity.
  - Spec alignment: `SPEC.md` requires keeping all grouped result evidence for
    the OTOBO ticket article.
  - Tasks:
    - Include per-evidence NVT name/OID, host, opaque port, threat, CVEs when
      present, and description when present.
    - Keep optional descriptive fields optional; missing CVEs or description
      must not fail the run.
    - Add a test with two grouped results containing different optional fields
      and assert both are represented in the article.

- [x] Verify and document OTOBO Generic Interface no-match response shapes.
  - Finding: `extract_required_id_list()` now requires a known response field
    for search operations. That catches rejected operations, but the codebase
    does not include fixture coverage for the actual OTOBO no-match response
    shapes administrators will see.
  - Spec alignment: `SPEC.md` requires harmless preflight searches to fail
    when OTOBO rejects fields/classes/credentials, but not when a valid narrow
    search simply returns no matches.
  - Tasks:
    - Capture or document accepted no-match response shapes for `TicketSearch`
      and `ConfigItemSearch`.
    - Add fixture tests for those no-match shapes.
    - Update `README.md` troubleshooting notes if the expected no-match
      response depends on OTOBO Generic Interface route configuration.

- [x] Rerun verification after closing the above tasks:
  - `uv run python -m unittest discover -p '*_test.py'`
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
