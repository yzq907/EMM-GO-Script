# EMM GO Script

Go-based test tools for EMM gateway, download, LDAP, Redis, QUIC, TLS, CPU load, KDC authentication, and SGP-PAM load testing scenarios.

## Tools

| Directory | Purpose |
| --- | --- |
| `EMMProxy` | EMM TCP/TLS tunnel forwarding stress test |
| `EMMProxy-2` | GM TLS tunnel file download test |
| `TLS-Test` | Custom TLS extension tunnel stress test |
| `quic-client` | QUIC SPA authentication and token generation test |
| `emm-download` | One-shot concurrent download test |
| `emm-download-2` | Duration-based continuous download stress test |
| `ldap` | LDAP Bind authentication stress test |
| `redis-test` | Redis test data write/check/clean tool |
| `cpu_load_controlle` | Local CPU load generator |
| `sgp-xcad` | Kerberos KDC authentication stress test |
| `pam-loadtest` | SGP-PAM asset inventory generation, distributed SSH/RDP/VNC/Web/MySQL capacity and stability load testing |

Each tool directory contains its own `README.md` with configuration and usage details.

## Configuration

Real runtime files such as `config.json`, `config.yaml`, CSV user/session/token data, logs, binaries, and backup files are intentionally ignored. Use the provided `config.example.*` and `*.example.*` files as templates, then create local runtime files in the corresponding tool directory.

## Verification

Each directory is an independent Go module. Run tests from each tool directory:

```bash
go test ./...
```

For `pam-loadtest` specifically:

```bash
cd pam-loadtest
go test ./...
```

`pam-loadtest/AGENTS.md` records the verified SGP-PAM test history, known issues, release-package rules, and follow-up guidance for future agents.
