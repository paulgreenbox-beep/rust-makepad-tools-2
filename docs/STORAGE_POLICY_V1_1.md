# Storage policy v1.1

The authoritative machine-readable policy is
experiments/ai-execution-workspace/storage-policy.json. It is unchanged from
the compiled source snapshot, not a model-controlled setting.

- Enforcement: monitored_soft_limit; hard_quota_enforced=false.
- Single-app owned writable-layer ceiling120,000,000,000bytes; host SSD reserve
  10,000,000,000bytes. Warning96GB, cleanup108GB, stop-growth114GB.
- Approved soft profile focus_trace71. Scenario growth1GiB, one growth512MiB,
  cumulative host evidence256MiB and maximum4capture attempts.
- RAM1GiB/CPU1 container. Host/VM/build admission2GiB. No waivers.
- Observe actual SizeRw together with exact CID/image/owner/nonce/creation and
  startup identity. Unknown usage is not zero. No external writable mounts.
- Check before create/stage/upload, before budgeted growth and runtime requests.
  A growth refusal must not prevent normal quit/owned cleanup.
- Keep host staging, owned writable layer, shared image/cache/VHDX and evidence
  accounting separate. A120GB policy value is not an OS filesystem hard quota.
- Cleanup preserves accepted Core references and never removes foreign data.
  The existing oversized-registry cleanup refusal remains unresolved.

The template is not authority to provision a container or bypass operator review.
