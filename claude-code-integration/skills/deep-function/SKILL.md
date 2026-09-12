---
name: deep-function
description: Inspect and edit a selected Ghidra function with bounded code, explicit return status and deliberate persistence through GhidrAssistMCP.
argument-hint: "<project-path> <function> [objective]"
---

Project path: `$0`. Function selector: `$1`. Full invocation: `$ARGUMENTS`; the text after the first two arguments is the objective. Resolve the project path to one exact ID using paged discovery. Use conversation selectors if paths contain whitespace or arguments are absent; do not split opaque program IDs into positional arguments. Carry out edits only when the user has authorized them.

Read [references/operating-guide.md](references/operating-guide.md), discover the exact `program_id`, and verify the selected program's language, revision, changeability and save capability. Keep selection explicit even if GUI focus changes.

Follow decompile → selected edit with `return_code` → inspect → save. Use only arguments present in the connected tool schema. Native name-preservation may retain the existing function name when a prototype changes; verify `function_entry`, `mutation_status`, and `stored_prototype`, rather than looking up the requested prototype name as a new symbol. Bound code and query output; distinguish an applied mutation from stale or unavailable post-mutation verification. Do not repeat an edit automatically after a timeout, decompiler failure or uncertain result.

Save with the program save tool when persistence is included in the authorized scope; VT sessions and project sessions have separate persistence scopes. Generic task IDs are process-local and do not survive a JVM restart.
