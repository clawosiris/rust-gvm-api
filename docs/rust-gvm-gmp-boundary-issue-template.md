# rust-gvm GMP Boundary Issue Template

Use this template when a `rust-gvm-api` change would require local GMP command
construction, response parsing, or wire/display-name normalization. File the
issue against `clawosiris/rust-gvm`.

## Title

Support typed GMP handling for `<command-or-response>` used by rust-gvm-api

## Problem

`rust-gvm-api` needs to call or parse `<command-or-response>` without owning GMP
wire details locally. The current `rust-gvm` API does not expose typed support
for the required gvmd behavior.

## Observed gvmd Behavior

- gvmd version:
- Command or response involved:
- Payload or response fragment:
- Error message, if any:

## rust-gvm-api Impact

- Blocked endpoint or feature:
- Blocked test:
- Current local workaround, if one exists:

## Required rust-gvm Change

- Add or adjust typed command builder support for:
- Add or adjust typed response parser support for:
- Normalize wire/display-name values into stable typed values:

## Acceptance Criteria

- `rust-gvm` has unit tests for the command/response behavior.
- `rust-gvm-api` can remove any local GMP workaround.
- `rust-gvm-api` architecture tests pass without expanding the known violation list.
