# E2E Harness

Usage:

```bash
scripts/e2e/run.sh <test-name> <test-script> [args...]
```

The runner writes logs to `logs/e2e/<test-name>-<timestamp>.log` and captures
full command outputs in `logs/e2e/outputs/`.

Test scripts are sourced and can call helpers from `scripts/e2e/lib.sh`:

- `e2e_run "label" cmd ...`
- `e2e_assert_last_status <code>`
- `e2e_assert_last_contains "substring"`
- `e2e_assert_last_regex "regex"`
- `e2e_assert_last_eq "expected"`

Minimal example:

```bash
# tests/e2e/version.sh

e2e_run "version" cargo run -- --version
e2e_assert_last_status 0
e2e_assert_last_contains "rano"
```

Then run:

```bash
scripts/e2e/run.sh version tests/e2e/version.sh
```
