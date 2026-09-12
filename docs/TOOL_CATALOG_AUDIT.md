# Tool and feature catalog audit

Reviewed 2026-09-11 against checkout base `5b3a058` and the working modernization changes. This is a fresh source and contract review, not a claim that every operation has been exercised in a live Ghidra installation. No user program, database, repository, or script was executed during this audit.

## Contract baseline

The implementation targets MCP **2025-11-25** through Java SDK 2.0.1. The standards review identified **2026-07-28** as the newer protocol revision; that revision requires a separate migration and is not advertised here. The [2025-11-25 tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) defines `isError`, optional `outputSchema`, and structured results. Output schemas now have an adapter in the shared tool interface; adopting the adapter is separate from defining accurate per-operation result contracts.

Tool-result pages (`offset`, `limit`, `has_more`) are application data. They are distinct from MCP [cursor pagination on discovery endpoints](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination). A stable program is required between search pages; this update does not introduce snapshot-isolated cursors.

## Implemented by the catalog review

| Area | Previous behavior | Updated behavior | Verification |
| --- | --- | --- | --- |
| `search_functions_by_name` | `limit=0` could still return one match; fractional/overflow values truncated; no continuation; locale-dependent case folding | Exact integers; `limit` 1-1000, nonnegative offset; one additional matching row determines `has_more`; `next_offset`; typed structured rows; `Locale.ROOT`; legacy text preserved | Proxy-program paging, exact-limit, invalid-input, locale tests |
| `search_strings` | Capped result looked complete; invalid input and no-program failures lacked error flag; no continuation | Same bounded page contract; explicit `isError`; structured string previews limited to 256 characters with original length and `value_truncated`; text preserved | Multi-page, no-further-match, long-value, invalid-input, locale tests |
| `get_strings` / `list_strings` | Numeric casts accepted negative/fractional/overflow values; missing program looked successful | Published exact bounds and runtime validation; `isError` failures; interrupt-aware listing | Contract tests; existing complete-count semantics retained |
| Query cancellation | Search loops ignored thread interruption | Three updated query loops stop on interruption and return an error without presenting partial results as complete | Source inspection; transport cancellation remains a separate concern |
| `scan_instructions` | Runtime capped instructions and mnemonic arrays, but schema omitted these bounds | Schema publishes existing 1-100000 instruction bound and 256 mnemonic maximum | Existing scan validation suite extended |
| `run_script` | Inherited `openWorldHint=false` although user scripts can perform arbitrary external I/O | `openWorldHint=true`; no execution capability change | Annotation assertion |
| Inventory | README/count checks did not provide a complete machine-readable current catalog | Runtime-generated sorted `build/reports/tool-catalog.json` from `getAllTools()` with schemas, annotations, and descriptions | `ToolCatalogInventoryTest`; no tool execution |

The 1000-row maximum is an intentional compatibility tightening for the three updated read queries. Clients needing larger results should page. Existing tool names and legacy text remain available.

## Complete family review and remaining work

| Family | Current capabilities and strengths | Remaining work / decision |
| --- | --- | --- |
| Program identity and GUI context | Stable program identity support; open-program inventory; program metadata; current location/function | Publish exact output schemas; distinguish GUI-only context from headless capability in discoverable descriptors |
| Functions, strings, imports, exports, data, segments, namespaces, relocations | Legacy text lists, several filtered/paged lists, cached queries; richer function inventory | Search and function-inventory result contracts are implemented above. `ListFunctionsTool` still materializes all matches; `ListDataTool`/legacy import path still use weak integer casts. Migrate remaining lists individually with total-vs-page semantics and direct-runtime error tests |
| Decompilation, basic blocks, stacks, statistics, class inspection | Shared decompiler; task-aware code execution; multiple text/pcode/structured formats | Existing cancellation/cache repairs at base HEAD are retained. Introduce result-format-specific schemas, bounded instruction/AST output, and retrievable result resources; do not equate generic task results with standard MCP Tasks |
| Xrefs and call graphs | Address/function/call-graph modes; bulk xrefs tool | Legacy `XrefsTool` and `GetCallGraphTool` still call Ghidra graph queries with `TaskMonitor.DUMMY`; exact-limit output may say limited without a lookahead. Add bounded traversal, cancellation, graph cursors and consistent edge schemas |
| Batch context, symbols, memory and tables | Bounded batch support, structured per-item results; program provenance and explicit continuation in newer tools | Concrete schemas and existing nested input bounds implemented for all five batch queries; short-read/exception partial results made explicit. Broader aggregate payload budgets and immutable result cursors remain deferred |
| Instructions, function candidates, register context | Bounded ranges; task monitoring; preview-oriented candidates; explicit register context | Existing instruction limits now advertised. Harmonize inclusive/half-open address conventions, cancellation-result semantics and maximum nested arrays without changing established range meaning |
| Comments, variables, types, structures, bookmarks, renaming | Consolidated action tools plus compatible legacy entry points; many mutators wrapped in program transactions | Multi-action tools correctly require conservative mutation annotations across all actions. Audit destructive hints on deletion/overwrite actions; introduce action-specific schema constraints where SDK adapter permits; keep old names |
| Memory/code mutation and assembly | Explicit mutations, patch/assembly tools and individual function creation | Keep current capability scope. Validate preview/commit/result semantics and annotate unsaved changes consistently; avoid adding automated exploitation or target workflows |
| Project lifecycle, persistence, repository, import/export | Exact program selectors; saves with per-object results; repository and session controls; three sensitive tools disabled by default | Unified feature discovery for GUI/headless support; separate mutation success from persistence success; document shared repository/network effects. Do not enable disabled tools merely to simplify discovery |
| Analysis and scripting | Analysis settings/control, task-backed analysis, bounded captured script output; standalone and consolidated script tools | Open-world annotation repaired on `run_script`. Script cancellation remains cooperative; unify lifecycle reporting and descriptor constraints without expanding script execution behavior |
| Signature export, byte/string matching, label/region transfer | Existing local comparison and reviewed transfer utilities | Document provenance, scoring semantics, cross-program freshness and transaction outcomes; retain current local analysis scope |
| Native GDT/C parser/type import | Read-only GDT catalog; staged C parsing; selected dependency-aware import with freshness token and preview | Native helpers already validate numeric ranges that generic schemas do not always publish. Add operation-specific schemas. Preserve documented limitation: `max_bytes` covers explicit inputs, not transitive includes or macro expansion |
| Native program diff and FID | Aligned read-only diff; FID database inventory and paged identification with candidate continuation | Publish result schemas, installed-database prerequisites and continuation contracts; retain explicit non-relocation/non-merge limitations |
| Native Version Tracking | Session lifecycle, correlators/options, match review, selected markup preview/apply/unapply; freshness tokens, paging and task monitors | Separate session/destination save outcomes already represented. Publish operation-specific output schemas and input bounds. Test cancelled/partial native operations with fixture programs before broad refactoring |
| BSim connections/databases | Secret-free profiles; installed templates; database metadata/create/update/drop/maintenance | Keep explicit destructive operations and native backend differences visible; broad common property bags reduce discoverability. Generate descriptors from the actual operation record and avoid irrelevant properties per operation |
| BSim corpus/signatures | Signature generation, ingestion, metadata, removal, exports, corpus rebuild | Durable jobs and artifact-relative paths are strengths. Keep restart/resume explicit; audit large-result retention limits and progress per operation |
| BSim query/matching | Executable/function catalogs, vectors, comparison, overview, queries, program matching, preview/apply | Distinguish native similarity scores from probabilities, maintain reviewed apply semantics; add exact result contracts and retrieval hints |
| BSim job control | Persistent list/get/results/resume/cancel/purge with pagination | Remains a separate durable job namespace from generic tasks; consolidate discovery/documentation before considering any adapter to standard Tasks |
| Generic tasks and runtime discovery | Existing status/cancel/list plus modernization `wait_task` and `runtime_capabilities` | Team lifecycle work handles bounded waits and cancellation. Application task IDs are not standard MCP task IDs; avoid advertising protocol support that is absent |
| Compatibility aliases | Fourteen names share their target execution and enabled state; eight consolidated legacy tools retain distinct schemas | Preserve all public names. Alias descriptions now point to canonical tools; opt-in curated profiles can reduce model context while preserving default compatibility |

## Priority follow-up matrix

| Priority | Work | Status |
| --- | --- | --- |
| P0 | Preserve error semantics and bounded continuation on common searches | Implemented in this review |
| P0 | Validate SDK/schema migration and all registrations | Team integration checks; current inventory fixture included |
| P1 | Accurate schemas for high-use batch, code, native and VT result variants | Concrete contracts applied to six batch/inventory tools, two searches, runtime discovery and task controls; remaining families still need staged adoption |
| P1 | Legacy query failures: consistently set `isError` for missing program/address and invalid parameters | Fixed in three tools; remaining legacy query families deferred |
| P1 | Runtime-enforced numeric/array bounds reflected in all schemas | Scan and three queries fixed; native, VT and legacy families remain |
| P1 | Explicit cancellation through legacy graph/list/expensive-query operations | Search loops improved; graph and full-count scans deferred |
| P1 | Aggregate response byte budgets and immutable/paged large-result resources | Deferred; row caps alone cannot bound unusually long symbols or large nested payloads |
| P2 | Optional curated tool profiles with family-level discoverability | Deferred; preserve default legacy tool access |
| P2 | Action-specific discriminated schemas and transactional result vocabulary | Deferred; retain old inputs while adding constraints with tests |
| P2 | Golden schema fixtures and live GUI/headless smoke matrix | Runtime snapshot foundation implemented; fixture-backed native validation still needed |

## Verification and limits

The initial focused suite exercises invalid numeric values (including fractions and overflow), wrong types, missing programs, exact-limit vs additional-match distinction, offsets, empty continuation pages, locale independence, bounded string previews, existing scan bounds and script annotation. The inventory test reads descriptors without executing registered tools.

Run with Java 25+ and the configured Ghidra installation:

```powershell
.\gradlew.bat '-PGHIDRA_INSTALL_DIR=C:\GHIDRA\FRESH_GHIDRA' test --tests ghidrassistmcp.tools.SearchQueryContractTest --tests ghidrassistmcp.tools.ScanToolsValidationTest --tests ghidrassistmcp.ToolCatalogInventoryTest --console=plain
```

Focused verification completed successfully: **11 tests passed**, no failures or skips, using Java 25 and `C:\GHIDRA\FRESH_GHIDRA`. The complete runtime inventory follows. Each row is a registered public name, including disabled defaults and aliases, rather than a README-derived feature claim.

## Applied batch contracts and applicability

The follow-up implementation applies the schemas to real tools, rather than stopping at a shared hook. Each descriptor exposes a concrete completion schema, and the backend validates successful results before caching or task completion. Long-running tools advertise the shared union of that completion contract and the custom in-memory task submission contract.

| Tool | Applied output contract | Applied behavior and validation |
| --- | --- | --- |
| `query_address_context_batch` | Required `results/count/errors/truncated/partial`; typed address, function, symbol, data/instruction, byte-read and xref records; success/error row alternatives | Input array and numeric limits published. Short bytes, omitted symbols/xrefs and row errors make `partial=true`. All-exception batches use `isError=true` |
| `search_symbols_batch` | Required query/matches/scanned/truncated per query and results/count/truncated envelope; typed symbol records | Existing 64-query, 1000-match and 100000-scan limits published. Matched, unmatched and scan-capped results validated |
| `read_memory_batch` | Required byte counters, hex, space, endian/type, optional precise numeric value/value_error or row error; aggregate byte budget/count/errors/truncated/partial | Short reads now set aggregate `truncated` and `partial`. Unsigned 64-bit values stay decimal strings. All-exception batches use `isError=true` |
| `read_memory_table` | Required row index/address or row error; dynamic named fields restricted to integer, decimal string or typed short-read object; count/errors/truncated/partial | Input row/stride/field bounds published. Empty table remains successful. Short-read fields set aggregate incomplete-result flags |
| `xrefs_batch` | Typed endpoints, reference types, operand/source, flow booleans, symbols/function/external metadata and row error alternatives; scan/count/errors/truncated/partial | Existing per-address, operand and scan limits published. All-exception batches use `isError=true`; actual asynchronous submission and completion validated |
| `function_inventory` | Typed function name/address/size, entry bytes/hash, caller/callee counts and optional edges; required page offset/limit, scan counts, lower-bound/exactness flags and next offset | Adds `total_matched_is_exact` and actionable `next_offset`; zero-sized pages do not falsely advance. Scan ceilings require increasing `scan_limit`, not pretending offsets resume a scan |

Both legacy search tools also retain their prose and now include a standalone serialized JSON text fallback equal to `structuredContent`. The runtime inventory confirms **12 of 145 public descriptors** currently declare concrete output schemas. The remaining 133 descriptors have not been declared schema-complete by this audit; absence of a schema does not mean absence of structured data.

The 12 descriptors are: `cancel_task`, `function_inventory`, `list_tasks`, `query_address_context_batch`, `read_memory_batch`, `read_memory_table`, `runtime_capabilities`, `search_functions_by_name`, `search_strings`, `search_symbols_batch`, `wait_task`, `xrefs_batch`.

Completion validation checks a tool's completed structured payload against its own concrete schema before caching or marking a task completed. Discovery for `function_inventory` and `xrefs_batch` advertises a union that also accepts the custom task submission snapshot. The ProgramDB tests validate both actual immediate submissions and eventual results against that advertised union, and separately validate completed direct results against completion-only schemas. Accepting a submission envelope does not count as validating the completed analysis payload.

**Follow-up validation: 22 tests passed, no failures or skips.** Nine tests use a fresh disposable `ProgramDB` for nested valid/error/short-read/empty/scan-limited results across all six tools, actual async lifecycle envelopes and completed payloads, plus malformed required-field/nested-type rejection through the SDK's JSON Schema validator. The other tests cover batch decoding/budgets, inventory compatibility, search behavior/JSON fallback and complete runtime catalog generation. These tests do not operate on user projects.

Applied here: concrete result contracts, published existing input bounds, explicit incomplete-result semantics, error flags, standard structured/text representation, actual result validation. Still deferred: per-operation native/VT/BSim schemas, all remaining legacy query contracts, immutable result resources, resumable scan cursors, and aggregate serialized-byte budgets across every tool.

## Verified runtime inventory

The successful catalog fixture reports **145 registered public names**, **142 enabled by default**, **14 compatibility aliases**, and **12 descriptors with output schemas**. Disabled defaults: `export_program`, `import_file`, `scripts`.

`RO` = read-only hint, `RW` = potentially mutating, `D` = destructive hint, `O` = open-world hint, `I` = idempotent hint. These are the actual advertised values, not assurances that every annotation is ideal. Multi-action tools use conservative mutation classification. Output schema `-` means the descriptor has not adopted one; it does not mean the tool has no structured results.

| Public tool | Family | Advertised hints | Default | Output schema | Alias target |
| --- | --- | --- | --- | --- | --- |
| `analysis_control` | Analysis/scripts | RW | Enabled | - | - |
| `analysis_options` | Analysis/scripts | RW | Enabled | - | - |
| `analyze_function` | Inventory/search | RO | Enabled | - | - |
| `analyze_program` | Analysis/scripts | RW | Enabled | - | - |
| `assemble_code` | Code/memory mutation | RW / D / I | Enabled | - | - |
| `batch_rename` | Annotation/types | RW / I | Enabled | - | - |
| `bookmarks` | Annotation/types | RW / I | Enabled | - | - |
| `bsim_apply_matches` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_cancel_job` | BSim job control | RW / O | Enabled | - | - |
| `bsim_compare_functions` | BSim operation | RO / O | Enabled | - | - |
| `bsim_configure_connection` | BSim operation | RW / O | Enabled | - | - |
| `bsim_create_database` | BSim operation | RW / O | Enabled | - | - |
| `bsim_database_info` | BSim operation | RO / O | Enabled | - | - |
| `bsim_drop_database` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_export` | BSim operation | RW / O | Enabled | - | - |
| `bsim_generate_signatures` | BSim operation | RW / O | Enabled | - | - |
| `bsim_get_function` | BSim operation | RO / O | Enabled | - | - |
| `bsim_get_job` | BSim job control | RO / O | Enabled | - | - |
| `bsim_get_results` | BSim job control | RO / O | Enabled | - | - |
| `bsim_ingest` | BSim operation | RW / O | Enabled | - | - |
| `bsim_list_connections` | BSim operation | RO / O | Enabled | - | - |
| `bsim_list_executables` | BSim operation | RO / O | Enabled | - | - |
| `bsim_list_functions` | BSim operation | RO / O | Enabled | - | - |
| `bsim_list_jobs` | BSim job control | RO / O | Enabled | - | - |
| `bsim_list_templates` | BSim operation | RO / O | Enabled | - | - |
| `bsim_maintain_database` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_match_programs` | BSim operation | RW / O | Enabled | - | - |
| `bsim_overview` | BSim operation | RW / O | Enabled | - | - |
| `bsim_preview_matches` | BSim operation | RO / O | Enabled | - | - |
| `bsim_purge_job` | BSim job control | RW / D / O | Enabled | - | - |
| `bsim_query_functions` | BSim operation | RW / O | Enabled | - | - |
| `bsim_query_program` | BSim operation | RW / O | Enabled | - | - |
| `bsim_query_vectors` | BSim operation | RW / O | Enabled | - | - |
| `bsim_rebuild_corpus` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_remove_connection` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_remove_executables` | BSim operation | RW / D / O | Enabled | - | - |
| `bsim_resume_job` | BSim job control | RW / O | Enabled | - | - |
| `bsim_update_database` | BSim operation | RW / O | Enabled | - | - |
| `bsim_update_metadata` | BSim operation | RW / O | Enabled | - | - |
| `bulk_region_transfer` | Compare/transfer | RW / I | Enabled | - | - |
| `bulk_transfer_labels` | Compare/transfer | RW / I | Enabled | - | - |
| `cancel_task` | Task lifecycle | RW | Enabled | Yes | - |
| `class` | Code/graphs | RO | Enabled | - | `classes` |
| `classes` | Code/graphs | RO | Enabled | - | - |
| `clear_code_ranges` | Code/memory mutation | RW / D | Enabled | - | - |
| `close_program` | Project/persistence | RW / I | Enabled | - | - |
| `comments` | Annotation/types | RW / I | Enabled | - | - |
| `create_data_var` | Annotation/types | RW / I | Enabled | - | - |
| `create_function` | Code/memory mutation | RW / D / I | Enabled | - | - |
| `create_functions_at_addresses` | Code/memory mutation | RW / I | Enabled | - | - |
| `create_memory_block` | Code/memory mutation | RW | Enabled | - | - |
| `datatype_archive_catalog` | Native GDT/diff/FID | RO | Enabled | - | - |
| `datatype_import_selected` | Native GDT/diff/FID | RW | Enabled | - | - |
| `delete_data_type` | Annotation/types | RW / D | Enabled | - | - |
| `disassemble_at` | Code/memory mutation | RW / D / I | Enabled | - | - |
| `export_function_signatures` | Compare/transfer | RO | Enabled | - | - |
| `export_program` | Project/persistence | RW / O | Disabled | - | - |
| `fid_identify_functions` | Native GDT/diff/FID | RO | Enabled | - | - |
| `fid_list_databases` | Native GDT/diff/FID | RO | Enabled | - | - |
| `function_byte_matcher` | Compare/transfer | RO | Enabled | - | - |
| `function_inventory` | Inventory/search | RO | Enabled | Yes | - |
| `get_basic_blocks` | Code/graphs | RO | Enabled | - | - |
| `get_binary_info` | Program/context | RO | Enabled | - | - |
| `get_call_graph` | Code/graphs | RO | Enabled | - | - |
| `get_code` | Code/graphs | RO | Enabled | - | - |
| `get_current_address` | Program/context | RO | Enabled | - | - |
| `get_current_function` | Program/context | RO | Enabled | - | - |
| `get_data_at` | Batch/memory query | RO | Enabled | - | - |
| `get_data_type` | Annotation/types | RO | Enabled | - | - |
| `get_data_vars` | Inventory/search | RO | Enabled | - | - |
| `get_entry_points` | Inventory/search | RO | Enabled | - | - |
| `get_exports` | Inventory/search | RO | Enabled | - | - |
| `get_function_info` | Inventory/search | RO | Enabled | - | `analyze_function` |
| `get_function_signature` | Inventory/search | RO | Enabled | - | - |
| `get_function_stack_layout` | Code/graphs | RO | Enabled | - | - |
| `get_function_statistics` | Code/graphs | RO | Enabled | - | - |
| `get_functions` | Inventory/search | RO | Enabled | - | - |
| `get_hexdump` | Batch/memory query | RO | Enabled | - | `get_data_at` |
| `get_imports` | Inventory/search | RO | Enabled | - | - |
| `get_namespaces` | Inventory/search | RO | Enabled | - | - |
| `get_program_info` | Program/context | RO | Enabled | - | `get_binary_info` |
| `get_register_context` | Scan/context | RO | Enabled | - | - |
| `get_relocations` | Inventory/search | RO | Enabled | - | - |
| `get_segments` | Inventory/search | RO | Enabled | - | - |
| `get_strings` | Inventory/search | RO | Enabled | - | - |
| `get_task_status` | Task lifecycle | RO | Enabled | - | - |
| `import_file` | Project/persistence | RW / O | Disabled | - | - |
| `list_binaries` | Program/context | RO | Enabled | - | - |
| `list_data` | Inventory/search | RO | Enabled | - | `get_data_vars` |
| `list_data_types` | Annotation/types | RO | Enabled | - | - |
| `list_exports` | Inventory/search | RO | Enabled | - | `get_exports` |
| `list_functions` | Inventory/search | RO | Enabled | - | `get_functions` |
| `list_imports` | Inventory/search | RO | Enabled | - | `get_imports` |
| `list_namespaces` | Inventory/search | RO | Enabled | - | `get_namespaces` |
| `list_programs` | Program/context | RO | Enabled | - | `list_binaries` |
| `list_relocations` | Inventory/search | RO | Enabled | - | `get_relocations` |
| `list_segments` | Inventory/search | RO | Enabled | - | `get_segments` |
| `list_strings` | Inventory/search | RO | Enabled | - | `get_strings` |
| `list_tasks` | Task lifecycle | RO | Enabled | Yes | - |
| `open_program` | Project/persistence | RW / I | Enabled | - | - |
| `parse_c_declarations` | Native GDT/diff/FID | RW | Enabled | - | - |
| `patch_bytes` | Code/memory mutation | RW / D / I | Enabled | - | - |
| `patch_instruction` | Code/memory mutation | RW / D | Enabled | - | - |
| `program_diff` | Native GDT/diff/FID | RO | Enabled | - | - |
| `project_files` | Project/persistence | RW / D | Enabled | - | - |
| `project_repository` | Project/persistence | RW / D / O | Enabled | - | - |
| `query_address_context_batch` | Batch/memory query | RO | Enabled | Yes | - |
| `read_memory_batch` | Batch/memory query | RO | Enabled | Yes | - |
| `read_memory_table` | Batch/memory query | RO | Enabled | Yes | - |
| `rename_symbol` | Annotation/types | RW / I | Enabled | - | - |
| `rename_symbol_batch` | Annotation/types | RW / I | Enabled | - | `batch_rename` |
| `run_script` | Analysis/scripts | RW / D / O | Enabled | - | - |
| `runtime_capabilities` | Program/context | RO | Enabled | Yes | - |
| `save_program` | Project/persistence | RW / I | Enabled | - | - |
| `save_project_session` | Project/persistence | RW / I | Enabled | - | - |
| `scan_function_candidates` | Scan/context | RW / I | Enabled | - | - |
| `scan_instructions` | Scan/context | RO | Enabled | - | - |
| `scripts` | Analysis/scripts | RW / D / O | Disabled | - | - |
| `search_bytes` | Batch/memory query | RO | Enabled | - | - |
| `search_functions_by_name` | Inventory/search | RO | Enabled | Yes | - |
| `search_strings` | Inventory/search | RO | Enabled | Yes | - |
| `search_symbols_batch` | Batch/memory query | RO | Enabled | Yes | - |
| `set_comment` | Annotation/types | RW / I | Enabled | - | - |
| `set_data_type` | Annotation/types | RW / I | Enabled | - | - |
| `set_function_prototype` | Annotation/types | RW / I | Enabled | - | - |
| `set_local_variable_type` | Annotation/types | RW / I | Enabled | - | - |
| `set_register_context` | Scan/context | RW | Enabled | - | - |
| `string_anchor_matcher` | Compare/transfer | RO | Enabled | - | - |
| `struct` | Annotation/types | RW | Enabled | - | - |
| `types` | Annotation/types | RW / I | Enabled | - | - |
| `variables` | Annotation/types | RW / I | Enabled | - | - |
| `vt_add_matches` | Version Tracking | RW | Enabled | - | - |
| `vt_apply_markup` | Version Tracking | RW | Enabled | - | - |
| `vt_correlate` | Version Tracking | RW | Enabled | - | - |
| `vt_correlators` | Version Tracking | RO | Enabled | - | - |
| `vt_markup` | Version Tracking | RO | Enabled | - | - |
| `vt_matches` | Version Tracking | RO | Enabled | - | - |
| `vt_review_matches` | Version Tracking | RW | Enabled | - | - |
| `vt_session` | Version Tracking | RW | Enabled | - | - |
| `vt_sessions` | Version Tracking | RO | Enabled | - | - |
| `vt_unapply_markup` | Version Tracking | RW | Enabled | - | - |
| `wait_task` | Task lifecycle | RO | Enabled | Yes | - |
| `write_bytes` | Code/memory mutation | RW / D | Enabled | - | - |
| `xrefs` | Code/graphs | RO | Enabled | - | - |
| `xrefs_batch` | Batch/memory query | RO | Enabled | Yes | - |
