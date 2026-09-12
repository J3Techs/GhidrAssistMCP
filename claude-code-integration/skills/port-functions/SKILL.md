---
name: port-functions
description: Port selected function annotations between compatible Ghidra programs through GhidrAssistMCP's bounded discovery, matching, preview and transfer contracts.
argument-hint: "<source-project-path> <destination-project-path> [scope]"
---

Source project path: `$0`. Destination project path: `$1`. Full invocation: `$ARGUMENTS`; use the text after the first two arguments as the requested scope.
Resolve the first two positional paths once against the complete paged inventory and require one open program per path. Paths with spaces need an explicit selector supplied in conversation instead of positional parsing. Pass the resulting exact program IDs as JSON strings to tools; never split IDs on whitespace. If arguments are absent, use the programs and scope already established in the conversation or request the missing selection.

Use the shared server guide in [references/operating-guide.md](references/operating-guide.md) first. Discover with compact `runtime_capabilities` and paged `list_binaries`; copy exact opaque `program_id` values into every subsequent call. Names and project paths may be ambiguous, and IDs must never be reconstructed or truncated.

Check language/compiler compatibility, revisions, writability and save capability before matching. Use only tool arguments and schemas advertised by the connected server. Prefer native VT or a matcher mode explicitly reported as supported; masked or architecture-specific modes remain guarded until the server advertises them.

Review candidates and evidence, then use whole-operation dry run/preview where available. Preserve existing analyst names and signatures unless replacement is explicitly requested. A preview token is optional for direct legacy calls and must be fresh when supplied; never invent one. Apply the user-authorized scope, inspect per-row outcomes, then save the destination program and any VT session independently when requested or included in the authorized workflow.

If a tool or argument is unavailable, report the required server upgrade and stop that workflow step. Resume from persisted program/VT state and PORT provenance, not a client-only progress file or a stale task ID.
