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
- Unit tests belong in sidecar files named `*_test.rs`, not inline `mod tests` blocks.
- Integration tests, contract tests, and other higher-level behavior tests belong under the crate's `tests/` directory.
- Always run `cargo fmt --all -- --check` to validate code formatting before considering the work complete.
- Always run `cargo clippy --workspace --all-targets --all-features -- -D warnings` to validate code changes before considering the work complete.

## GMP ownership boundary

- All GMP command construction, GMP response parsing, and GMP wire/display-name normalization belongs in `clawosiris/rust-gvm`.
- `rust-gvm-api` may call typed `rust-gvm` command builders and typed response parsers, then map typed values into gateway domain and REST models.
- If a fix requires parsing, normalizing, or constructing GMP command or response wire details inside this repository, stop the implementation instead of adding a local workaround.
- When stopping on this rule, report an issue against `clawosiris/rust-gvm` that describes the missing typed command/response support, the observed gvmd behavior, and the blocked `rust-gvm-api` endpoint or test.
- If the GMP boundary architecture test fails, do not broaden its allowlist unless the violation is already tracked as a temporary upstream issue against `clawosiris/rust-gvm`.
