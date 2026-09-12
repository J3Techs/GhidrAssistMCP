# MCP and Codex modernization — September 11, 2026

Three independent agent tracks reviewed standards/transport, task lifecycle/cache, and the complete tool catalog. A coordinating pass handled dependency migration, schema adaptation, resource targeting, runtime diagnostics, Codex integration and cross-track validation. The implementation started from `5b3a058`, which already contained the earlier decompiler, cache-finalization and session-isolation fixes.

## Shipped in this working tree

| Area | Implemented result |
| --- | --- |
| Maintained dependencies | MCP Java SDK 2.0.1, Jetty 12.1.13 EE10/Servlet 6, Jackson 2.21.1 BOM. Generated dependency staging prevents obsolete `lib` JARs from entering compilation or the extension archive. |
| Schema contracts | Map-based input schemas retain JSON Schema keywords. Twelve tools have concrete output contracts, including nested batch rows and task metadata. Completed results are validated before caching or task success; async descriptors accept completion or submission metadata. All 145 registrations build with SDK validation enabled. |
| Transport | Strict SDK header negotiation by default, explicit 16 MiB request limits, configured-listener Origin validation, retained server handles, bounded shutdown and partial-start cleanup. Legacy SSE and an explicit Accept-compatibility switch remain available. |
| Resources | Six program resources are advertised as URI templates; runtime capabilities is a concrete resource. Encoded exact selectors resolve the requested open program. Missing and invalid targets receive appropriate MCP errors. |
| Discovery | New `runtime_capabilities` tool exposes the same runtime data as the resource, including precise supported-protocol and task-lifecycle limits. Catalog updates do not advertise unimplemented list-change notifications. |
| Tasks | New `wait_task` waits up to 30 seconds for completion or a state-version change. Supplied progress tokens produce actual request-scoped progress. Submissions return structured identity, snapshots are atomic, arguments are frozen, and program context carries version-aware identity. |
| Cancellation and listing | Cancellation control can interrupt a mutating worker without waiting on that worker's mutation lock. Missing/failed task responses carry error flags. `list_tasks` returns bounded pages and complete UUIDs. |
| Cache | Admission is serialized and bounded by both count and serialized bytes: 32 MiB total and 1 MiB per entry by default. Oversized results still reach the caller but are not cached. |
| Queries | Two searches and six batch/inventory tools expose concrete result contracts and input limits. Short reads, partial failures, exact-total indicators and continuation are explicit. Search failures, locale handling and interruption are corrected. Instruction scan schemas publish enforced bounds; script I/O has the correct annotation. |
| Result compatibility | Server responses preserve a standalone JSON text representation alongside structured results, including when program context decorates an existing JSON response. Task controls provide stable structured error codes. |
| Codex | A repository workflow skill, a validated 27-tool configuration example, and connection/result/recovery guidance are included. Global configuration and installed skills were not changed. |

The runtime-derived catalog contains **145 registered names**, **142 enabled by default**, and **14 compatibility aliases**. Every registered name is listed in the [catalog audit](TOOL_CATALOG_AUDIT.md), with feature-family assessment, annotation/default state, output-schema status and alias relationship. **12 of 145 descriptors declare output schemas**; the other 133 retain their established contracts. The [applied conformance matrix](MCP_APPLIED_CONFORMANCE.md) maps standards requirements to actual execution tests and explicitly identifies missing behavior.

## Standards boundary

The current stable Java SDK implements protocol revisions through **2025-11-25**. MCP's latest **2026-07-28** specification changes the core to stateless requests and introduces different discovery, per-request capabilities, routing and extension semantics. This release does **not** claim to implement that revision merely because dependencies were updated. [Official Java SDK release matrix](https://github.com/modelcontextprotocol/java-sdk/blob/main/CHANGELOG.md), [official MCP July release](https://blog.modelcontextprotocol.io/posts/2026-07-28/).

The custom task tools are not advertised as the standardized Tasks extension. Existing optional prompts/resources are preserved; new dependencies on deprecated logging/sampling/roots features were not introduced. Authentication, proxy policy, Apps UI and extension negotiation require explicit designs rather than capability flags alone. Detailed dispositions and primary sources are in the [standards audit](MCP_STANDARDS_AUDIT.md).

## Validation

Validation used publisher-checksummed Temurin **25.0.4.1+1** from a task-local toolchain and **Ghidra 12.0.2** at `C:/GHIDRA/FRESH_GHIDRA`. Java settings were changed only in child build commands.

The final coordinated test run completed **200 tests across 54 suites: 198 passed, two skipped, zero failures or errors**. The skips are the opt-in external BSim backend tests. Actual HTTP tests exercise initialization, truthful capabilities, stable catalogs, resource/template/prompt discovery, selected resource reads and error codes, input validation before dispatch, declared output validation, JSON fallback, and progress token correlation. Disposable ProgramDB fixtures exercise the six batch/inventory output contracts. Separate backend tests prove malformed sync/async completions cannot populate the cache or produce successful task completion.

The archive's 21 JARs were checked against the staged dependency files byte-for-byte; there were no obsolete SDK, Jetty or Jackson JARs. The Codex example's 27 names all exist in the runtime catalog. The workflow skill passed the skill validator. Source whitespace checks passed.

Cross-review identified and resolved two integration issues before packaging: resource selector failures needed protocol-specific error classification, and server status accessors needed synchronization with shutdown. Existing native VT/FID/type/project tests continue to use disposable fixtures. No live user program, installed extension, global Codex setting or running production Ghidra instance was modified.

## Next modernization boundaries

1. **July 2026 protocol transport:** adopt a Java implementation when available or design and independently validate a separate stateless adapter. Cover discovery, metadata, caching/routing headers, extension negotiation, replay semantics and backward compatibility together.
2. **Results across the remaining catalog:** extend concrete output schemas, error codes, byte bounds and immutable result paging. Retain usable text fallback where clients depend on it. Large legacy results are not globally bounded by this update.
3. **Durable generic work:** add a journal and retrievable result artifacts with restart reconciliation. Current generic task history, result storage and pending queue remain process-local and lack global admission bounds. BSim's existing journal remains separate.
4. **Measured workflows:** add request correlation and phase/size diagnostics, then use observed query and decompiler costs to guide batching, catalog profiles or session reuse. Current cache byte budgets are admission estimates, not an exact JVM heap limit.
5. **Invocation admission and timing:** add actual rate limiting and bounded queue admission. The fixed task pool is not a rate limiter. Bound stalled progress sends separately: the monotonic wait deadline cannot cap the SDK's synchronous transport send.
6. **Optional features:** evaluate prompt/resource completion and MCP Apps against actual client support and concrete user workflows. Extend progress where an active request benefits; detached workers cannot reuse a completed request's token.

See [Codex integration](CODEX_INTEGRATION.md), [task/cache contracts](TASK_LIFECYCLE_AUDIT.md), [tool catalog](TOOL_CATALOG_AUDIT.md), [standards audit](MCP_STANDARDS_AUDIT.md) and [applied conformance evidence](MCP_APPLIED_CONFORMANCE.md).
