---
name: ghidrassist-mcp
description: Use GhidrAssistMCP to inspect and annotate open Ghidra programs, follow analysis tasks, and verify saved project state. Apply when working through this server's tools; distinguish its live program state from offline database files.
---

Read `runtime_capabilities(include_programs=false)` and page `list_binaries` when connecting or diagnosing a changed runtime. It reports supported protocol revisions, build identity, enabled tool counts, open programs, available native services, and recovery limits without probing remote databases.

Use `list_binaries` or the capabilities result to select an exact `program_id` for related work. A display name can be ambiguous, and the active GUI window can change between calls. Ghidra project paths such as `/folder/program` are different from host filesystem paths. Program resource URI names must be percent-encoded; an encoded exact project path or program ID can disambiguate names.

Prefer bounded queries. `search_functions_by_name` and `search_strings` return structured `has_more`/`next_offset` pages. Paging assumes the same program revision; restart the query if the database changes. `get_code` supports structured native output and explicit limits. Inspect truncation flags rather than treating a partial result as complete. Some older tools still return prose or duplicated JSON text, so inspect the advertised schema and actual result.

Use the batch context, symbol, memory and xref tools when related queries share a program. Inspect both `isError` and per-row errors: a partially successful batch remains usable, while an all-exception batch is an error. Short reads are explicit. For `function_inventory`, check `total_matched_is_exact` and `scan_truncated`; an offset does not resume a scan stopped at its ceiling. Increase the bounded scan limit when needed. Prefer structured fields over parsing the JSON text fallback.

When an operation returns `task_id`, use `wait_task(include_result=true)` for a bounded wait with a complete result when it fits, or `get_task_status` for the retained terminal result. Fast reads may complete inline. A payload-retention error does not change the operation status. `timeout_ms` controls the wait only. Supply `after_version` to wait for a later task state; omit it when waiting for terminal completion. A wait timeout means work may continue. Request `cancel_task` only when stopping the operation is intended, and wait for its settled status. Application task IDs are separate from the MCP Tasks extension.

Task controls expose `error.code`, `error.message`, and `error.retryable`; use these to distinguish invalid arguments, a missing task, and a retryable wait interruption. Request-scoped progress, when the client supplies a token, describes elapsed waiting and does not prove the worker is advancing.

Generic task records are in memory and disappear with their manager/JVM. Preserve `manager_instance_id` and task ID in progress notes. After a restart, inspect database state before repeating a mutation. BSim has its own durable journal and resume rules.

For authorized edits, inspect operation results and dirty state, then use `save_program` when persistence is part of the request. A successful program save and a project/VT/BSim session save can be distinct outcomes. Use native preview tokens for operations that expose preview/apply semantics; regenerate stale previews instead of overriding them.

Do not infer a live backend connection or installed runtime update from a successful source build. Building creates an extension archive; the running Ghidra JVM uses its loaded extension until it is restarted with the updated installation.

The shared client-neutral operating guide is packaged at `src/main/resources/ghidrassistmcp/operating-guide.md`. Claude and Grok wrappers are versioned under `claude-code-integration/` and `grok-integration/`; their client configuration and spill-file behavior require client-version validation.
