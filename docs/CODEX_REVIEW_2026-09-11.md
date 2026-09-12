# Codex integration review — 2026-09-11

Historical baseline: the findings below describe `50cd32a`. Several were fixed in `5b3a058`; the subsequent [multi-agent modernization report](MODERNIZATION_2026-09-11.md) records current implementation and validation. Preserve this document as the original review rather than treating its findings as still-open defects.

GhidrAssistMCP already has a broad native Ghidra toolset. The next investment should make its existing tools easier for Codex to discover, compose, wait on, and recover from. The strongest transferable work in grok-oauth-mcp is its result handling, explicit lifecycle, client diagnostics, and measured operational feedback.

This is a source-based architecture and integration review, with identified correctness issues. It is not a certification of every native operation or a live Codex/Ghidra interoperability test.

## Scope and baseline

- GhidrAssistMCP: clean working tree at `50cd32a` before this document was added. Reviewed dispatch, transport, tool registration, task management, caching, program identity, representative query/decompilation tools, result helpers, native-service documentation and test coverage.
- grok-oauth-mcp: `66ccae4` plus existing uncommitted changes. The comparison includes those working-tree changes, especially result packing and the September 10 log audit. No Grok code, configuration, or running session was changed.
- Existing strengths: 143 registered names including compatibility aliases; read/write annotations; exact program selectors; batch queries; structured native output; isolated decompiler sessions; serialized MCP writers; retained async program consumers; persistent headless project access; VT/type preview workflows; and a durable BSim journal.
- `docs/REVIEW_VALIDATION.md` reports an earlier run of 127 tests: 125 passed and two environment-dependent tests skipped. The current review attempted `gradlew.bat -PGHIDRA_INSTALL_DIR=C:\GHIDRA\FRESH_GHIDRA test --console=plain`; it stopped during build evaluation because active Java is 21 and the build requires 25+. No tests executed in this review.

## Correctness work to prioritize

| Priority | Finding and source | Consequence | Recommended change |
| --- | --- | --- | --- |
| P1 | The Streamable HTTP compatibility servlet keeps a single `lastSessionId` and uses it when a request omits its session identity. `transport/LenientStreamableTransportServlet.java:28,69–74,98–110`. | A shared endpoint cannot reliably preserve client-session boundaries using a process-wide last-seen value. This is particularly unsuitable for simultaneous Codex tasks or multiple MCP clients. | Remove implicit reuse of another session. Let the transport enforce explicit session identity; isolate any indispensable legacy compatibility behavior. This finding is from source inspection; no cross-session probing was performed. |
| P1 | Default text decompilation and p-code call the native decompiler with `TaskMonitor.DUMMY` and the options timeout, although the public schema exposes `timeout_seconds` and the async path supplies a task monitor. `tools/GetCodeTool.java:92,104–107,166–169,253–257`. | Cancellation and requested timeout behavior differ between default text and structured output. Cancellation can remain pending until native work finishes. | Pass the same monitor and validated timeout through both representations. Make the scope of every public limit explicit. |
| P1 | Several legacy `get_code` failure branches return text without `isError=true`; generic task completion checks that flag to distinguish failure from completion. `tools/GetCodeTool.java:110–147,171–198,259–270`; `tasks/McpTaskManager.java:105–109`. | Missing functions and decompilation failures can be recorded as completed tasks. Codex must infer failure by parsing prose. | Introduce a shared error result with stable code, message, retryability and context. Preserve useful partial results separately. Audit the other legacy tools using the same pattern. |
| P2 | Long-running execution returns into `executeToolAsync` before the normal cache write, and its completion path does not populate the cache. Both `get_code` and `function_inventory` declare themselves long-running and cacheable. `GhidrAssistMCPBackend.java:421–452,477–494`. | With default async enabled, completed work does not warm the normal cache; repeated queries can repeat expensive computation. | Share result finalization between sync and async paths. Cache only successful, complete results whose program revision and relevant options stayed valid across execution. |
| P2 | Sync results are decorated with active-window context before caching; cache hits return that decoration unchanged. `GhidrAssistMCPBackend.java:428–432,444–452,846–900`. | A cached answer can describe a previously active window even when the target data is still valid. | Cache the raw result and decorate each response using current display context plus immutable target identity. |
| P2 | Generic task lookup returns prose for unknown IDs, absent managers, and non-result states. `tools/GetTaskStatusTool.java:45–78`. | Failed/cancelled/not-found/running states do not have a consistent machine-readable contract. | Always return an explicit task envelope; mark lookup errors as errors and retain the operation's terminal status alongside its result. |

The cache key also reduces serialized arguments to Java's 32-bit string hash and does not configure canonical map ordering (`cache/McpCache.java:55–68`). During the cache work, use canonical arguments or a strong digest with equality protection. Do not retain a correctness-sensitive cache identity based only on a small hash.

## What to transfer from Grok

| Grok implementation | GhidrAssistMCP today | Transfer and adaptation |
| --- | --- | --- |
| `src/result-packer.ts`: bounded wire size, concise text digest, structured result, separate omission counters | `ProjectToolSupport`, `BsimSupport`, and `VTSupport` serialize essentially the same payload into both text and `structuredContent` | Add a common result serializer, explicit budgets, and content-specific loss accounting. Keep a full-text compatibility representation where needed. |
| `grok_start`, `grok_follow`, `grok_wait`: explicit lifecycle and retained terminal output | Generic submit/status/cancel tools, in-memory history; separate durable BSim jobs | Add a wait/follow operation over generic tasks, with stable result references and restart-aware records. Preserve BSim's specialized checkpoint semantics. |
| `src/client-profile.ts` and initialize handling: client name/version and declared capabilities | The server handler receives `exchange` but passes only arguments to the backend | Capture a per-session request context for diagnostics, progress and representation selection. Use declared capabilities for protocol features; client names can select tested defaults only. |
| Server instructions plus `.agents/skills/grok-mcp-workflow` | Analysis prompts and Claude integration material, but no comparable Codex integration package | Provide concise server workflow instructions, a Codex skill and tested registration examples. |
| `src/observability.ts` and the September 10 audit: correlated phases, result loss and latency measurements | Ghidra logs, UI event listeners and aggregate cache stats | Add structured per-call telemetry and bounded diagnostics, then prioritize improvements from observed workload data. |
| MCP registration/output-contract tests and protocol fixtures | Substantial direct Java and ProgramDB tests, little evident successful transport/client coverage | Add transport contract coverage and a small reproducible Codex smoke suite against disposable projects. |

Grok's 65,536-byte response cap is an implementation choice, not a Codex protocol limit. Its one-year timeout example is also not a suitable default to copy blindly into Ghidra. Choose Ghidra's initial budgets from representative outputs and measured work durations.

## Proposed Codex experience

### 1. Consistent, bounded results

Introduce a versioned envelope for new or explicitly opted-in representations:

```json
{
  "schema_version": 1,
  "status": "completed",
  "request_id": "...",
  "program": {"program_id": "...", "modification_number": "..."},
  "summary": "Returned 100 function records.",
  "data": {},
  "pagination": {"next_cursor": null},
  "loss": {"rows_omitted": 0, "text_bytes_omitted": 0},
  "warnings": []
}
```

The MCP text block should be a useful digest. Structured data should contain the result. Add output schemas to the registration layer; the current `McpTool` interface and tool builder expose input schemas and annotations but no output-schema contract. Async submission, progress and completion must all fit the declared schema.

Budget the complete serialized response, including metadata. A row count alone is insufficient: symbol names, comments, p-code operands and byte strings vary greatly in size. Default text disassembly currently traverses the entire function, while structured output has item limits. Make both representations bounded and disclose what was omitted.

Keep large results retrievable through opaque result IDs and resource URIs with bounded pages. Where an explicit export is useful, return a real artifact reference. On a remote Ghidra host, a server-local Windows path alone is not usable by Codex; offer retrieval through MCP. Preserve complete records so the agent can fetch more evidence instead of asking Ghidra to regenerate it.

Use separate loss fields for result data, preview text, and optional metadata. Grok's audit illustrates why a single `truncated` flag triggers unnecessary recovery calls. Bind cursors to the query and program revision so a changed database cannot silently shift a paginated result.

### 2. Waitable, recoverable work

Keep existing task APIs compatible. Add a bounded `wait_task` or `follow_task` operation returning a task ID, revision/cursor, status, progress and optional terminal result. It should wake on completion, relevant progress, cancellation settlement, or the caller's wait deadline. A wait timeout means the operation is still running; it must not imply native execution stopped.

Use progress notifications when a progress token is supplied. The current transport's 15-second keepalive is connection maintenance, not an application task progress contract. Do not depend on notifications alone for result retrieval.

Journal generic task identity, start/finish state and result references. After a JVM restart, mark unfinished work interrupted and require reconciliation before replaying mutations. A durable record preserves evidence; it does not keep native Ghidra work alive. Extend `McpProgramContext` beyond name/path/file ID to retain the existing version-aware `program_id` and relevant revision metadata.

Add queue admission bounds: `newFixedThreadPool(4)` limits workers but uses an unbounded pending queue, and generic history cleanup currently happens only at submission time. Report queue wait separately from execution. Consider returning a fast completed result within a short grace period before allocating a visible task, but measure the value first.

### 3. Discoverable tools and workflow guidance

Expose the existing `ghidra://runtime/capabilities` payload as a small read-only tool as well as a resource. Add client/session diagnostics, async mode, enabled feature groups and actionable prerequisites. Keep remote backend health explicitly unprobed unless requested.

Provide a curated Codex catalog emphasizing orientation, exact program selection, bounded queries, task/result retrieval and saving. Preserve the full catalog and legacy aliases. The 143 names include aliases and specialized administration tools; they are not 143 independent core workflows. Measure selection errors and catalog bytes before choosing the final subset.

Codex already supports per-server `enabled_tools` and `disabled_tools`, so an initial profile can be configuration rather than a new dynamic discovery subsystem. Avoid changing global tool enablement when a second client connects. If server-side profiles are later added, keep them session-scoped or configure separate endpoints with explicit behavior.

Add short server instructions covering the normal order: inspect capabilities and programs, select an exact program, use bounded queries, follow any returned task, inspect the result, and save when the requested changes require persistence. A Codex skill should explain project paths versus host paths, dirty versus saved state, and recovery after lost connections. Package the skill where user analysis work can discover it; a repository-local skill only helps tasks opened in this repository.

Existing annotations are a strength. Consolidated tools such as `comments`, `types` and `bookmarks` correctly advertise mutation because some actions write. Add narrowly scoped read-only entry points only if measured approval or scheduling friction warrants them; do not mislabel mixed tools as read-only.

### 4. Evidence and operational diagnostics

Record request/task IDs, client version, target identity, queue/lock wait, execution time, serialization time, cache outcome, result bytes and omission counts. Keep routine telemetry to metadata; make full argument/result logging an explicit choice. A bounded diagnostics tool should report counts and latency percentiles and link to local details where appropriate.

Build a small baseline around actual maintenance and analysis workflows: locate a function, inspect bounded decompilation, retrieve a large inventory page, follow an async operation, reconnect for its result, and verify a saved annotation in a disposable project. Measure tool calls per completed workflow, output bytes, cache reuse, status-call frequency, and task failure classification. This supplies evidence for catalog reduction, batching and decompiler reuse.

Keep the isolated decompiler-session design initially. Pooling native decompilers introduces lifecycle and concurrency complexity; fix the bypassed cache and measure remaining startup cost first.

## Suggested delivery order

1. **Correctness and contract baseline:** session handling, consistent error flags, monitor/timeout propagation, async cache finalization, fresh context decoration, and immutable task identity. Add focused regression coverage.
2. **Codex usability:** common bounded result format, output schemas, capabilities tool, wait/follow API, registration guide and workflow skill. Retain compatibility paths and add client-level contract checks.
3. **Recovery and measurement:** generic journal/result storage, paginated retrieval, queue limits, structured diagnostics and workload baselines. Adapt BSim integration without discarding its existing journal.
4. **Measured optimization:** tune the curated catalog, add selected read-only wrappers or bounded composite reads, and consider decompiler pooling only where data supports it.

Keep core protocol and execution improvements client-neutral. A thin Codex integration package should select useful defaults and teach the workflow. Grok's ACP runtime, OAuth process handling, named-pipe owner routing and child-agent controls solve different problems and do not need to be transplanted into this in-process Ghidra server.

## Current Codex documentation checked

Official documentation confirms Streamable HTTP configuration, tool allow/deny lists, per-tool output token budgets and configurable startup/tool timeouts. It currently documents a 60-second default tool timeout. These are client settings; they neither cap native Ghidra execution automatically nor prove that cancellation has settled. See [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

The source recommendations above are based on the local repositories. Support for a future standardized task extension should be established from negotiated capabilities and client/version tests before replacing the compatible task tools.
