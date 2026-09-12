# Native analysis tools

These six tools use installed Ghidra APIs. They run through the existing cancellable MCP task manager and do not apply labels or analysis implicitly.

| Tool | Behavior |
|---|---|
| `datatype_archive_catalog` | Opens a GDT read-only; returns SHA-256, exact type paths, lengths and IDs with offset/limit paging. |
| `parse_c_declarations` | Parses declaration `text` or explicit `header_paths` and `include_paths` into an isolated, persistent staged GDT. Requires a selected program's language/compiler or explicit values. |
| `datatype_import_selected` | Previews exact type paths and dependency conflicts, then imports selected definitions in a program transaction. |
| `program_diff` | Compares two exact open program selectors with category and inclusive range filters. Returns bounded differing addresses and native warnings; does not relocate or merge programs. |
| `fid_list_databases` | Catalogs configured local FID databases and their libraries/languages, reporting unreadable or incompatible files individually. |
| `fid_identify_functions` | Queries an exact function entry or a bounded page of functions; returns candidate names, hashes, scores and library provenance. |

For type import, call with `path`, exact canonical `names`, and a `conflict_policy` of `preserve`, `replace`, or `fail`. The default is a dry run. Inspect `conflicts` and `can_apply`, then repeat with `dry_run=false` and the returned `preview_token`. Tokens bind the archive contents, target program revision, selection and policy. Preview includes dependencies, bitfield base types, and prior archive-linked definitions even if renamed locally. Explicitly save the program afterward.

Parsing returns native preprocessor/C diagnostics. Successful artifacts remain beneath the system temporary directory's `ghidrassistmcp-staging` folder; `staging_path` identifies the archive to inspect/import. Failed staging artifacts are cleaned up. Parser calls are serialized because Ghidra's header parser temporarily changes process output streams. `max_bytes` bounds explicit inputs only: transitive includes, macro expansion and native parser memory are not covered. Cancellation is cooperative.

FID paging accepts `offset`, `max_functions`, `limit` and `candidate_offset`. When truncated, continue with both returned `next_offset` and `next_candidate_offset` and unchanged query parameters; this preserves candidates when a result cap falls within one function. Native scores are not probabilities. No database, no compatible language, unhashable functions, and no matches are distinct results. Unexpected native failures are MCP errors.

Validation uses disposable x86 ProgramDBs, a real persisted FID library and native seeker, header parsing/import, linked-type rename conflicts and exact-range ProgramDiff. Installed third-party FID collections and other architectures require their own validation.
