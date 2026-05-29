# Performance Test Slice

This crate hosts the first intentionally narrow performance lane for the compose-backed REST gateway.

Current scope:

- one simple read scenario against seeded data: `list-port-lists-read`
- one simple write scenario with cleanup: `create-delete-target-write`

## Reproducibility Contract

- Run against the checked-in compose development stack and its seeded first-boot data.
- Execute single-threaded so weekly samples do not compete with each other inside one test run.
- Keep the read scenario tied to a stable seeded resource and keep the write scenario self-cleaning.
- Treat the JSON reports in `dist/performance/` as the durable artifact for week-over-week comparison.

## Local Run

```bash
./scripts/compose-dev.sh up -d --build
./scripts/run-performance-tests.sh
```

The wrapper waits for the same readiness and seed-dependent REST resources as the E2E lane, then runs the ignored performance scenarios and writes JSON reports to `dist/performance/`.

## CI Interpretation

- CI uploads the JSON reports as workflow artifacts.
- This first slice does not enforce latency thresholds yet.
- Reviewers should compare the weekly artifact summaries against recent runs and investigate large regressions before broadening scope.
