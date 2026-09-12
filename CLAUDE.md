# CLAUDE.md

Guidance for working on the GhidrAssistMCP Ghidra extension. Treat the current source and tests as authoritative. Historical review notes are useful context, but are superseded when they disagree with implemented behavior.

## Architecture

- `GhidrAssistMCPPlugin` integrates with Ghidra and owns plugin/UI lifecycle.
- `GhidrAssistMCPServer` exposes the MCP Streamable HTTP endpoint under `/mcp`.
- `GhidrAssistMCPBackend` owns tool registration, admission, execution traits, task management, program selection, caching, and lifecycle draining.
- `McpTool` defines tool schemas, static catalog annotations, invocation traits, and execution methods. Mixed action tools may classify reads from their arguments; catalog annotations remain conservative.
- `src/main/java/ghidrassistmcp/tools/` contains consolidated and compatibility tools. Do not infer a fixed tool count.

Program selection uses exact identity. Prefer the `program_id` returned by discovery/capabilities when selecting a version-specific program; names and project paths can be ambiguous. A request retains a program lease for its full execution. Shutdown stops admission, drains active requests and workers, and releases leases only after the work settles. Task IDs are process-local and are not durable database identity.

## MCP and runtime distinctions

The server is reached at `/mcp`; use the MCP client transport and current server configuration rather than assuming legacy SSE/message paths. Source changes, a generated extension archive, an installed extension, and the extension loaded by an already-running Ghidra JVM are separate states. A successful Gradle build creates an archive; it does not update an installed or loaded runtime. Restart Ghidra after installing a rebuilt extension.

Regression fixtures use disposable in-memory or temporary ProgramDB instances and must not depend on live user databases. Live Ghidra state and persisted project state require explicit inspection and save operations when a task calls for them.

## Build and tests

Use the Gradle wrapper and pass the Ghidra installation explicitly. The locally verified Windows toolchain is:

```powershell
$env:JAVA_HOME = 'C:\Users\JResp\.codex\tmp\ghidrassist-modernization\jdk-25.0.4.1+1'
.\gradlew.bat -PGHIDRA_INSTALL_DIR='C:\Users\JResp\Desktop\ghidra_12.0.3_PUBLIC' test buildExtension --console=plain
```

On another machine, override `JAVA_HOME` and `GHIDRA_INSTALL_DIR` (or pass `-PGHIDRA_INSTALL_DIR`) with paths appropriate to that platform. Use `./gradlew` on Unix-like systems and `./gradlew.bat` on Windows. Do not assume a global Gradle installation.

Run focused tests while iterating, then the full `test` task before delivery. Tests cover protocol contracts, tool behavior, lifecycle and shutdown, task ownership, caching, and disposable ProgramDB/decompiler fixtures. Keep tests deterministic and bounded; do not connect them to a live Ghidra project.

## Workflow and safety

Inspect existing tests and local instructions before editing. Preserve unrelated working-tree changes. Keep mutations inside Ghidra transactions and report failures honestly. For post mutation verification, distinguish a committed mutation from verification that is unavailable or stale; never claim rollback or automatic retry unless the implementation actually performed it. Save program/project/session state explicitly when persistence is part of the request.

The implementation plan in `docs/MCP_UPGRADE_IMPLEMENTATION_PLAN.md` tracks upgrade work. Shared operating behavior belongs in `src/main/resources/ghidrassistmcp/operating-guide.md`; update both only when the requested change affects shared client guidance.
