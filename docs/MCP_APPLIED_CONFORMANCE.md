# Applied MCP conformance and remaining gaps

This matrix distinguishes behavior implemented and exercised over HTTP from optional features, deferred work, and SDK availability. The implemented protocol remains **2025-11-25**; **2026-07-28 is not implemented**. Merely upgrading dependencies or attaching a schema does not satisfy the application contract.

## Applied and tested

| Requirement or capability | Application behavior | Evidence |
| --- | --- | --- |
| Version negotiation | Actual server/client initialization negotiates `2025-11-25`. Runtime diagnostics explicitly deny July stateless and Tasks-extension support. | `StreamableProtocolIntegrationTest`; `AppliedProtocolConformanceTest.actualServerAdvertisesOnlyImplementedCapabilitiesAndReturnsStableToolCatalog` |
| Truthful initialization | Instructions explain exact program selection and custom task lifecycle. Tool-list-change, resource subscriptions, resource-list-change, prompt-list-change, and completions are not advertised. | Actual-server capability assertions in `AppliedProtocolConformanceTest` |
| Stable tool discovery | Repeated wire catalogs are equal and sorted; advertised descriptors include input schemas and behavioral annotations. Cancellation is marked mutating. | Actual-server catalog assertions in `AppliedProtocolConformanceTest` |
| Resource templates | Parameterized program URIs are templates; concrete runtime URI remains a resource. Full catalog exposes six program templates and seven prompts. | `StreamableProtocolIntegrationTest`; `GhidrAssistMCPServerTest` |
| Exact resource selection | Encoded names select the requested program even when another program is active. | `AppliedProtocolConformanceTest.resourceSelectionAndResourceErrorsSurviveTheHttpBoundary` |
| Resource error semantics | Unknown resource and missing program yield `-32002`; ambiguous or malformed encoded selectors yield `-32602` for this supported revision. | Four actual HTTP resource-error cases in `AppliedProtocolConformanceTest` |
| Input validation | Schema-invalid tool arguments produce an actionable `isError` result before the tool handler executes. Unknown tools produce protocol `-32602`. | Isolated handler counter and actual HTTP calls in `AppliedProtocolConformanceTest.sdkValidatesInputBeforeDispatchAndValidatesDeclaredSuccessfulOutput` |
| Declared success-output enforcement | SDK rejects a result violating its output schema, accepts a conforming result, and preserves intentional tool errors. The backend validates completed results before cache admission or asynchronous task success. | Same isolated HTTP contract test; `McpOutputContractTest` covers sync/async failure, rejected cache admission, valid cache admission and preserved errors |
| Structured result compatibility | Both server endpoint families apply a shared JSON text fallback while preserving structured content and metadata. Runtime and wait results contain a standalone serialized text block exactly equivalent to the structured result. | `AppliedProtocolConformanceTest` HTTP assertions; `McpOutputContractTest` checks context decoration, numerical JSON equivalence, metadata and idempotence |
| Request-scoped progress | `wait_task` emits optional `notifications/progress` with the exact string/integer token from that call. Values increase and describe elapsed waiting; no token means no notifications. | Numeric and string tokens over actual HTTP in `AppliedProtocolConformanceTest.waitProgressIsRequestedCorrelatedIncreasingAndDoesNotCancelTheTask` |
| Progress lifetime | Request context is removed on normal return and exceptions, restored for nested calls, and not inherited by background workers. Duplicate/nonfinite progress is suppressed. A failed notification sink disables further notifications without changing the tool result. | `McpRequestContextTest` |
| Wait versus task lifetime | Wait timeout returns a still-running task snapshot; it does not cancel the independent operation. | Actual HTTP wait test plus task lifecycle suite |
| Transport lifecycle | Stop/restart, duplicate-start rejection, failure cleanup and retry after a released port work. Status accessors synchronize with lifecycle updates. | `GhidrAssistMCPServerTest` |
| Origin and Accept handling | Local Origin validation is applied; strict Accept behavior is default, with explicit compatibility opt-in. | `McpOriginFilterTest`; `LenientStreamableTransportServletTest` |

Progress is optional, must use a supplied token, must increase, and must stop when its request completes. This implementation does **not** treat custom task IDs as negotiated experimental Tasks handles; progress is attached to the active `wait_task` call only. [Supported progress contract](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress)

## Applicable but incomplete or deferred

| Area | Remaining work and practical limit |
| --- | --- |
| Invocation rate limiting | Deferred. A fixed task worker pool and mutation lock are not an invocation rate limiter or bounded queue-admission policy. Add explicit admission/backpressure and recovery guidance before claiming this requirement is implemented. |
| Absolute HTTP wait deadline | The wait loop has a monotonic deadline, but SDK synchronous `progressNotification` uses an unbounded `Mono.block()`. A stalled transport send can exceed the wait budget. Moving tool handlers to an async exchange would permit a separately bounded send without detached notifications arriving after the result. |
| Progress for other long operations | The reusable request context exists, but this pass applies it to waiting. Detached background execution must continue using retained task state unless a future negotiated protocol supports a longer notification lifetime. |
| All application output contracts | Schema coverage and batch/task contracts are tracked in the tool-feature audit. A successful startup validates schema documents, not every possible tool result or partial failure. Keep concrete execution tests and validate completed async results before cache admission. |
| Discovery pagination | The current catalog fits one response. SDK list support does not mean the application has implemented cursor pagination. Introduce it if catalog growth requires it, with stable cursor semantics. |
| Dynamic catalog changes | Runtime enable/disable configuration currently requires restart for the advertised catalog. Notification capabilities remain false. |
| Remote/shared hosting | Authentication and authorization are not implemented by this pass. Origin validation does not replace them. No claim is made that arbitrary remote deployment is covered. |
| Resource invalidation | Resource subscriptions and change notifications are not implemented or advertised. |
| Exhaustive malformed-envelope handling | Tests distinguish invalid tool arguments and unknown tools. They do not constitute exhaustive JSON-RPC envelope, transport-header, or reconnection conformance certification. |

## Optional features without an application in this pass

MCP Apps, icons, elicitation, completion providers, and host sampling have no implemented application workflow here. They should not be advertised simply because an SDK exposes a builder. Existing prompt templates remain discoverable; no new elicitation or UI feature is claimed. Logging, Roots, Sampling, and legacy HTTP+SSE are deprecated by the July revision; no new application dependency on them was added. The SDK itself still includes logging support for the supported older revision.

## Structured content: exact revision boundary

Both revisions recommend a serialized JSON text fallback and require declared output schemas to match successful structured results. The July revision broadens `structuredContent` from an object to any JSON value; this server keeps object-shaped contracts for its supported revision. The SDK automatically inserts JSON fallback only when text content is empty, so application prose summaries require the explicit shared fallback now applied by the server. [2025 tools contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [July tools contract](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [SDK result validation implementation](https://github.com/modelcontextprotocol/java-sdk/blob/v2.0.1/mcp-core/src/main/java/io/modelcontextprotocol/server/McpAsyncServer.java)

July also requires a different discovery/lifecycle model, per-request capabilities, new result/cache fields, and redesigned extension negotiation. Those remain missing; they cannot be implemented by adding a version string to the current initialization response. The separate standards audit records the migration prerequisites.

## Executed validation

```powershell
$env:JAVA_HOME = 'C:/Users/JResp/.codex/tmp/ghidrassist-modernization/jdk-25.0.4.1+1'
./gradlew.bat -PGHIDRA_INSTALL_DIR=C:/GHIDRA/FRESH_GHIDRA test --tests ghidrassistmcp.AppliedProtocolConformanceTest --tests ghidrassistmcp.McpRequestContextTest --tests ghidrassistmcp.StreamableProtocolIntegrationTest --console=plain
```

**Seven tests passed**, including four additional HTTP conformance scenarios and two request-context tests. The earlier transport/server suite passed nine tests; the coordinator records the final integrated suite. All programs and tasks in these tests are synthetic; no live user Ghidra program was opened or changed.
