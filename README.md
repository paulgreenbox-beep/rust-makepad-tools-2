# Rust Makepad Tools 2 — v0.2.0

Experimental **source-only** Windows GUI MCP and owner-scoped Makepad runtime
tools. This is a separate compact repository; it does not replace
[Rust Makepad Toolkit](https://github.com/paulgreenbox-beep/rust-makepad-toolkit)
or an installed Codex MCP connection.

## Scope

- Existing20-tool MCP dispatcher, with stdio and shared HTTP source paths.
- Windows native UIA tree, AutomationId/control state and supported patterns.
- Official Makepad App Remote integration: trusted WidgetId inspection,
  addressed keyboard input, independent value/focus observations and native
  `/g` GPU capture. Keyboard fill is not semantic UIA SetValue.
- Experimental Windows Hidden, with visible mode only by explicit operator opt-in.
- Experimental Windows-host-controlled Linux/WSLC single-app owner, relay,
  executable provenance and cleanup helpers.
- Existing SessionId/generation ownership, Arbiter leases, cancellation boundaries
  and fail-closed refusals. No blind replay after dispatch or unknown outcome.
- Verification Economy/Core evidence-v2 source, owning tests and synthetic
  profiles. Source tests do not constitute native Core v2/L4b acceptance.

The host MCP does not compile or bundle Makepad. The Remote contract is pinned to
**71c9ddcbb9c01dd208f99621fdd71024a5d35c65** from
[official Makepad](https://github.com/makepad/makepad). Other SDK generations,
including105158e Studio/WebSocket, are not drop-in replacements for this HTTP
Remote path. Native UIA is a separate mechanism; pattern support varies by app.

## Build and verification

Windows x64, Rust1.97.1 or a reviewed compatible toolchain, MSVC C++ linker and
Windows SDK. The source capsule retains its original Cargo manifests/lockfile.
Populate the exact locked Cargo cache through your approved dependency-fetch
process, then:

```powershell
cargo build --release --locked --offline -j 1 -p toolkit-windows-automation --bin toolkit-windows-gui-mcp --features experimental-makepad-remote
cargo test --locked --offline -j 1 -p rudra-runtime
cargo test --locked --offline -j 1 -p toolkit-windows-automation --lib --features experimental-makepad-remote
node --test verification-economy/tests/core.test.mjs verification-economy/tests/identity-capture.test.mjs
python -m unittest discover -s experiments/ai-execution-workspace -p test_storage_policy.py
python -m unittest discover -s crates/toolkit-windows-automation/src/makepad_remote -p test_wslc_host.py
```

Reuse an existing Cargo target where appropriate. Host/build/runtime admission
is2GiB; no simultaneous heavyweight Cargo/GPU workloads. The optional synthetic
WSLC provenance suite and ModuleShell operator-integration tests are separate
gates and are not declared passed by the commands above.

## Connect read-only first

Use [the inert Codex example](config/codex-readonly.example.toml) after building
and independently hashing the executable. It exposes five observation tools
with approval prompt. The [20-tool backend catalog](docs/tools.json) is not a
grant to expose all of them. Do not overwrite another connection or globally
reload live servers.

Routing/profile examples contain zero placeholder hashes and neutral paths.
They are not approved launch authority. The trusted operator supplies exact
reviewed artifact/profile bytes, real hashes, owner, admission and evidence
scope. AI arguments cannot inject arbitrary executable paths, commands, PIDs,
endpoints, policies or foreign container attachments.

## Recorded qualification, with exact boundaries

The published implementation comes from the immutable package source used for
MCP candidate SHA256
`3F18B23C75E7FADDEF80B4EB1E431BCFA697359A7679732E7A5EAD025B763180`.
[Source provenance](docs/SOURCE_PROVENANCE.json) lists exact input hashes and
documentation/packaging and helper privacy changes. The two provisioning
helpers use a neutral operator root; they need their own source-bound runtime
qualification and must not reuse the private smoke receipts. No recovery EXE, private evidence or vendor
runtime is shipped; a new build is a different artifact.

| Observation | Actual declared scope |
|---|---|
| Windows Hidden input/readback/native frames/normal App exit | Earlier exact recovery candidate; not a new3F18 Windows certificate |
| WSLC via real Codex, ALPHA and independent readback | One source-bound3F18 single-container smoke on27 October2026 |
| NVIDIA/D3D12 | Makepad runtime observed RTX5060 Laptop GPU in that environment only |
| Native image and application lifecycle | Original875x600 `/g` PNG, App/root exit0, native Job0 and owned cleanup0 in that smoke |
| Fresh full Core v2/L4b for that WSLC recipe | NOT_RUN; the eight-call smoke is not its full acceptance contract |
| stdio/shared HTTP/UIA | Existing source and scoped proofs; complete current-source runtime/cancellation compatibility remains unaccepted |

## Mandatory limits

- **Permanent canary remains read-only.** Controlled mutations are restricted to
  approved owned fixtures and require exact identity, leases, actual focus,
  independent postconditions, healthy runtime and proven shutdown/cleanup.
- Codex may externally terminate its MCP child with exit1. Direct stdin EOF0,
  MCP child status, App/root exit and Job0 are distinct. Normal Codex-owned MCP
  child exit0 and persistent mutable canary acceptance remain WITHHELD.
- WSLC storage policyv1.1 monitors a120GB decimal software ceiling with a10GB
  host SSD reserve. **It is not a hard quota.** One container has1GiB RAM/1CPU.
- The cleanup registry reader has an unresolved size-limit blocker. No registry
  truncation, forced cleanup or acceptance weakening is included here.
- Canonical Toolkit router differs from this compiled package by three semantic
  forwarding methods. This publication uses the verified package snapshot;
  no equivalence with the dirty canonical tree is claimed.
- Linux semantic SetValue, full mutable multi-agent isolation, two-WSLC-session
  parity, arbitrary Linux app provisioning and production promotion are absent.
- The optional typed TextInput/Button app semantic adapter has unsupported native
  producers/unwired projections; its existence is not live arbitrary-app support.

See [Windows/WSLC setup boundaries](docs/WINDOWS_WSLC.md),
[storage policy](docs/STORAGE_POLICY_V1_1.md),
[known limitations](docs/KNOWN_LIMITATIONS.md) and
[app semantic contract](docs/APP_SEMANTICS.md). Publication is not deployment.

## License

First-party sources retain the existing [MIT LICENSE](LICENSE). Exact dependency
declarations and retained notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
[the license inventory](docs/dependency-licenses.json) and LICENSES/.
Makepad code/assets, GPU drivers, WSLC images/VHDX, external runtime binaries,
private routing, user configuration, raw process/session receipts, Office/CAD
source and model documents are not distributed.
