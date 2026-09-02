# pam-loadtest

SGP-PAM high-activity session load generator. SSH and MySQL use direct Go WebSocket replay; RDP, VNC, and Web use shared Playwright Chromium processes with isolated browser contexts.

## Build and test

```bash
go test ./...
go vet ./...
go build -o bin/pam-loadtest ./cmd/pam-loadtest
npm ci --prefix browser-worker
npx --prefix browser-worker playwright install chromium
npm test --prefix browser-worker
```

No credential, cookie, token, asset UUID, or account UUID belongs in Git. Formal multi-asset runs load the permission-restricted runtime manifest selected by `PAM_ASSET_MANIFEST`; legacy single-asset environment variables remain available only for local smoke diagnostics.

## Commands

```bash
bin/pam-loadtest validate configs/mixed-1000.yaml
bin/pam-loadtest run configs/mixed-1000.yaml
bin/pam-loadtest agent configs/mixed-1000.yaml
bin/pam-loadtest controller configs/mixed-1000.yaml
```

See `docs/runbook.md` before running any session against PAM. Current smoke and sizing evidence is in `docs/smoke-capacity-evidence.md`. A 1000-session execution requires explicit operator confirmation after staged small-scale tests.

The approved mixed 1000-session profile is SSH 600, RDP 200, VNC 50, Web 100, and MySQL 50. In distributed mode the Controller binds every job to a globally unique manifest asset before partitioning, waits for every Agent terminal report, and emits count-only JSON. Any Agent failure, timeout, missing/mismatched report, or duplicate asset fails the whole run.
