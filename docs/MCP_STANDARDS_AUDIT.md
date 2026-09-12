# MCP standards and transport audit

Reviewed 2026-09-11 against current upstream sources and the actual resolved Java artifacts. This is a supported-SDK modernization, **not a claim of complete 2026-07-28 protocol implementation**.

## Dependency and protocol baseline

The prior build requested MCP SDK 0.17.1 and Jetty 11.0.20. The update uses MCP SDK **2.0.1** (`mcp-core`, `mcp-json-jackson2`, and its BOM) and Jetty **12.1.13**, with the EE10 servlet module. The Java SDK's current active release targets **2025-11-25**; the older 1.1 and 0.18 lines receive security patches. Version 2.0.1 bounds transport reads. [Official Java SDK release history](https://github.com/modelcontextprotocol/java-sdk/blob/main/CHANGELOG.md)

Jetty 12.1 is supported, whereas Jetty 11 is EOL. The selected EE10 module provides Servlet 6 and permits retaining the servlet transport architecture. [Jetty downloads and support status](https://jetty.org/download.html)

Inspecting the actual 2.0.1 artifact confirms `McpServerTransportProviderBase.protocolVersions()` returns `2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`. The SDK initialization handler selects the requested supported version or returns its latest supported version for client acceptance. These are negotiation versions, not a promise that every optional feature is implemented.

The Ghidra build helper previously added every `lib/*.jar` to the classpath and extension. That could retain obsolete SDK jars alongside newly resolved versions. The accompanying build changes isolate resolved dependency staging; validation must use that isolated classpath, rather than accidentally compiling against old jars.

## Implemented server corrections

| Area | Result |
| --- | --- |
| Initialization | Both transports advertise concise workflow instructions through `McpBackend.getInstructions()`. |
| HTTP body limits | Both servlet providers explicitly cap request bodies at 16 MiB. |
| Origin validation | Shared filter checks a present Origin against configured listener host, scheme, and actual port. Localhost aliases are accepted for loopback listeners. Missing Origin remains valid for native clients; repeated, opaque, malformed, or mismatched origins are rejected. |
| Accept negotiation | SDK validation is the default. The former rewriting behavior requires `-Dghidrassistmcp.transport.lenientAccept=true`. Trailing `/mcp/` normalization remains. |
| Lifecycle | Retain protocol server handles; close transports with bounded waits on stop and startup failure; clean up providers whose server construction failed; reject duplicate start and support restart. |
| Resource discovery | Parameterized program URIs appear in `resources/templates/list`; concrete runtime resources remain in `resources/list`. |
| Resource errors | A missing resource returns the SDK's protocol error, rather than successful text containing an interpolated error object. |
| Registration | Resource and prompt setup failures abort startup instead of leaving partially advertised capabilities. Their registration order is stable. |

Origin validation and HTTP content negotiation belong to the supported transport contract. Native clients do not require a browser Origin. The filter is not authentication or a remote hosting feature; wildcard listeners accept no browser origins. [Supported transport requirements](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)

Parameterized URIs belong to template discovery, and resource failures use JSON-RPC errors. Resource subscription and resource-list-change notifications remain unadvertised. [Resource contract](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)

## Modern feature disposition

| Feature | Current disposition |
| --- | --- |
| Streamable HTTP | Preferred `/mcp` endpoint; existing session-oriented SDK protocol retained. |
| Legacy HTTP+SSE | `/sse` and `/message` retained for compatibility; no new dependence on this transport. |
| Tool schemas and annotations | SDK validates inputs using its schema support. Output schemas are introduced only where the result contract is actually implemented; annotations describe behavior and do not grant authorization. |
| Structured output | JSON-object structured results remain compatible with the supported protocol; output-schema declarations must match actual success responses. |
| Custom application tasks | `wait_task`, task status, cancellation, and retained results are application tools. They are not advertised as protocol Tasks support. |
| Progress | `wait_task` now emits increasing elapsed-wait progress only when its active request provides a string/integer token. A scoped context prevents forwarding these notifications from detached task workers. |
| Prompts/completions | Existing prompts remain; argument completion is not advertised. |
| Resources/subscriptions | Correct template discovery is implemented; subscriptions and invalidation streams require a separate lifecycle design. |
| Logging/roots/sampling | No new handlers added. SDK 2.0.1 internally advertises its logging capability; this is distinct from application logging feature work. |
| MCP Apps, elicitation, authorization | Not implemented in this pass. Optional features require a concrete host workflow and capability negotiation. |

The tool contract distinguishes protocol errors from execution errors (`isError`), supports annotations and output schemas, and uses JSON Schema 2020-12 by default. Tool-result pagination arguments remain application-specific; protocol cursor pagination belongs to discovery endpoints. [Supported tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

## July 2026 migration boundary

The **2026-07-28** revision removes initialization and protocol sessions, introduces `server/discover`, per-request version/capability metadata, routing headers, result discriminators, and cache metadata. It also replaces resource subscription management and permits broader JSON Schema/structured-value shapes. Logging, Roots, Sampling, and legacy HTTP+SSE are deprecated. These changes require a coordinated SDK/client migration; adding a header or declaring a new version would be incorrect. [Official July specification changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx)

The Tasks extension has a different lifecycle from the earlier experimental Tasks API: the server can return a task when supported, and clients use `tasks/get`, `tasks/update`, and `tasks/cancel`. A future implementation must negotiate this extension and implement its semantics; current custom task IDs must not be mislabeled as those handles. [Tasks extension specification](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks)

Next protocol migration acceptance criteria: an SDK implementing the new revision; explicit discovery/version tests; new per-request capability and error behavior; bounded subscription lifecycle tests; tested retry/idempotency behavior for mutations; and client compatibility before removing old transport negotiation. Existing explicit program and task handles provide useful application state independently of transport sessions.

See [applied conformance matrix](MCP_APPLIED_CONFORMANCE.md) for actual HTTP evidence, structured JSON fallback enforcement, and substantive remaining gaps such as invocation rate limiting and stalled progress-send deadlines.

## Validation

Using the publisher-verified JDK 25.0.4.1 and `C:/GHIDRA/FRESH_GHIDRA`:

```powershell
$env:JAVA_HOME = 'C:/Users/JResp/.codex/tmp/ghidrassist-modernization/jdk-25.0.4.1+1'
./gradlew.bat -PGHIDRA_INSTALL_DIR=C:/GHIDRA/FRESH_GHIDRA test --tests ghidrassistmcp.GhidrAssistMCPServerTest --tests 'ghidrassistmcp.transport.*' --console=plain
```

Result: **9 tests passed**. Tests cover template versus concrete-resource discovery, restart and duplicate-start behavior, recovery from a failed port bind, Origin checks, strict Accept defaults, compatibility normalization, and the existing independent synthetic-client initialization regression. All listener tests use local temporary listeners; no live Ghidra instance or user program was mutated. Broader integration results are recorded by the coordinating review.
