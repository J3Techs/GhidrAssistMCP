# MCP workflow upgrade release notes

This upgrade adds bounded program discovery, faster completion of short reads, explicit transfer previews, PORT checkpoints, and post-edit code inspection. Use the validation report to distinguish the tested source/archive from the extension loaded in an existing Ghidra JVM.

## Compatibility changes

- `bulk_transfer_labels` preserves analyst-origin names/signatures by default. Use explicit `name_policy=replace` or `signature_policy=replace` only when replacement is intended. All prototypes are validated during dry-run; an apply failure rolls back the call.
- `bulk_region_transfer` preserves analyst names, checks reviewed source/target revisions and rejects failed preflight plans. Exact comparisons require the complete compared window to match. Missing-function creation remains an explicit legacy option; porting skills require corroborated matches and recommend existing definitions.
- Masked matching requires decoded instructions and qualified architecture/context. Consult [the supported-mode table](MATCHER_SUPPORT.md). `mask_mode=none` is explicit raw-byte matching. Scores and capped searches never establish uniqueness by themselves.
- Fast task-capable reads may return their completion inline. Otherwise, `wait_task(include_result=true)` can return the complete operation result. Inspect the nested operation error separately from the wait status.
- Generic task admission and retention are finite. `SERVER_BUSY` is retryable; `RESULT_EXPIRED` and `RESULT_TOO_LARGE` describe retained payloads and do not mean a committed edit failed.
- Selected batch reads and function inventory reject results beyond 120,000 encoded bytes before context decoration. Reduce page/batch size and per-row limits. This ceiling counts both structured content and the JSON fallback; it does not bound native analysis allocation or scan cost.

## PORT checkpoints

Use `port_ledger(action=get,address=...)` on the exact source function to obtain `current_fingerprint`. Include `port_metadata` in each reviewed `bulk_transfer_labels` row:

```json
{
  "operation_id": "client-chosen-stable-id",
  "source_program_id": "exact ID from discovery",
  "source_address": "00001000",
  "source_fingerprint": "64 lowercase SHA-256 hexadecimal characters",
  "method": "reviewed native VT association",
  "evidence_reference": "optional bounded review reference"
}
```

A changed row records an `applied_unverified` NOTE bookmark in category `PORT` in the same transaction. One checkpoint per destination entry replaces earlier history; repeating a checkpoint does not append text. Metadata is rejected if it exceeds the bounded JSON format.

`port_ledger(list/get)` inspects saved or unsaved checkpoints. To verify, pass the target's freshly observed `expected_target_revision` and exact `operation_id`. The server resolves the source recorded in the checkpoint and compares source and destination fingerprints. Fingerprints cover language/compiler, entry, name, prototype, and every byte in the function body (maximum 1 MiB). Unsupported/missing bytes fail explicitly. This is identity and annotation verification, not semantic equivalence. Save the destination separately. Unsaved program IDs do not provide durable cross-session identity.

## Deep-function edits

`set_function_prototype`, `set_local_variable_type`, and their `variables` actions accept `return_code=true`, `max_chars`, and `verification_timeout_seconds`. Results distinguish committed mutation from `verified`, `stale`, or `unavailable` code inspection. Native signature application may preserve an existing analyst name or replace a default-origin name: use the returned function entry and actual stored prototype. Saving may change a program's opaque versioned ID; rediscover it before subsequent close/reopen operations.

## Packages and evidence

Claude and Grok wrappers are distributed separately from the extension. Both reuse the server's canonical initialization guide. Existing tool names, aliases, resources, and seven prompts remain available. Generic tasks remain process-local; BSim retains its separate job system.

Use [the conformance harness](VALIDATION_HARNESS.md), [client validation](CLAUDE_INTEGRATION.md), [Grok integration](GROK_INTEGRATION.md), and the final team report for tested versions and limitations. The archive includes a build source fingerprint. Installing an archive and verifying the restarted JVM are distinct release actions; do not close unsaved working programs merely to reload an extension.
