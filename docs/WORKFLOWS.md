# Safe project workflows

Use `list_binaries` before a mutation. Each entry includes a canonical `program_id`, project path, version and dirty/transaction state. Pass the exact project path or `program_id` to tools that accept `program_name`; missing and ambiguous selectors are rejected.

`save_program` saves one open Program database and verifies that it is clean afterward. It does not save FrontEnd session metadata, Version Tracking sessions, or repository state. Save those object types through their own workflows and treat each result independently.

For project file deletion, first call `project_files` with `action=delete`, `dry_run=true`, and the same target and `recursive` values. The preview is bounded to 10,000 entries and checks busy or dirty files. A real deletion requires `confirm=true`; recursive deletion reports the count completed if a native failure or cancellation occurs. Deletion is not an atomic transaction.

Async cancellation is a request. `CANCEL_REQUESTED` remains nonterminal until the worker stops, so a noncooperative native operation cannot be reported as finished prematurely. Retrieve the final task result after status settles; returned MCP error results retain their structured error payload.

Repository status reports version, dirty/busy/read-only state and native `can_*` predicates. Check-in refuses when `can_merge` is true; resolve that update through Ghidra's native merge UI before retrying.
