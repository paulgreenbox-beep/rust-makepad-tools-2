# Changelog

## v0.2.0 — 2026-10-28, separate source-only publication

- Publish the verified210-file package snapshot associated with source-bound
  MCP candidate3F18B23C75E7FADDEF80B4EB1E431BCFA697359A7679732E7A5EAD025B763180.
- Include existing Windows Remote/Hidden/UIA, stdio/shared HTTP, single-app WSLC,
  kernel-backed executable provenance, lease/evidence and owning test sources.
- Include storage policyv1.1 monitored_soft_limit, bounded process output,
  bootstrap/upload/capture/cleanup helpers and pure regressions.
- Complete the standalone Core package/integrity metadata without changing any
  Core implementation or acceptance policy. Keep all frozen Rust/Python/PowerShell
  runtime bytes unchanged except for two provisioning helpers and their contract
  fixture, whose personal guest paths are neutralized and explicitly not runtime
  recertified; publish a relative-path provenance index.
- Document actual earlier Windows and current WSLC qualification separately.
  Full new Core v2/L4b, registry cleanup, Codex child graceful shutdown and
  persistent mutable/production acceptance remain unclosed.
- Publish inert configuration examples, licenses and cheap source CI.

No compiled executable or system/MCP deployment is part of this release.
