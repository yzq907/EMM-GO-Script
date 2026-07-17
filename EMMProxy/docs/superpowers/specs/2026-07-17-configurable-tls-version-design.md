# Configurable TLS Version Design

## Goal

Allow the load test to force either TLS 1.2 or TLS 1.3 through `config.json` without changing the existing client count, session rotation, connection lifecycle, HTTP request, assertion, JTL, or statistics behavior.

## Configuration

Add one top-level field:

```json
"tls_version": "1.2"
```

Accepted values are exactly `"1.2"` and `"1.3"`. An omitted or empty value defaults to `"1.2"` for backward compatibility. Any other value causes startup to fail with a clear configuration error.

## TLS Behavior

Map the configured value to Go's TLS constants and assign the same value to both `tls.Config.MinVersion` and `tls.Config.MaxVersion`:

- `"1.2"` maps to `tls.VersionTLS12`.
- `"1.3"` maps to `tls.VersionTLS13`.

Using identical minimum and maximum versions prevents fallback or automatic negotiation to another TLS version. The selected TLS version is logged once when the program starts.

## Compatibility

Existing configurations without `tls_version` continue to use TLS 1.2. No load-generation or session-allocation behavior changes.

The existing cipher suite list remains unchanged. Go applies that list to TLS 1.2; TLS 1.3 cipher suites are selected by the Go TLS implementation and are not configured through `CipherSuites`.

## Files

- `main.go`: add the configuration field, validate and map it, and build `tls.Config` with the selected version.
- `config.json`: set `"tls_version": "1.2"`.
- `config.example.json`: document the same default.
- `main_test.go`: cover the default, TLS 1.2, TLS 1.3, and invalid-value cases.

## Verification

Run unit tests, race tests, and `go vet`. Runtime validation should verify that a TLS 1.2 configuration negotiates `0x0303` and a TLS 1.3 configuration negotiates `0x0304` when the selected server supports that version.
