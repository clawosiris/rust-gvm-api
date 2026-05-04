# AGENTS.md

## Specification-first workflow

- Always read the relevant specifications in `spec/` before making implementation changes.
- Align the implementation with the specifications.
- Do not change the specifications unless you were explicitly asked to do so.
- If the code and the specifications disagree, treat that as something to surface and resolve deliberately, not something to silently "fix" by rewriting the spec.

## Tests

- Always document the intent of tests.
- When adding or updating tests, make it clear what behavior, contract, regression, or edge case each test is meant to cover.
- Prefer test names and nearby comments that explain why the test exists, not just what commands it runs.
