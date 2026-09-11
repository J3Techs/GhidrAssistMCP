# Custom version consolidation

Consolidated on 2026-09-11 from published `J3Techs/GhidrAssistMCP:custom-tools`
commit `2f60648b2907de9d171fbfc030c0e93582e593ea`.

## Recovered sources

| Source | Disposition |
| --- | --- |
| Current GitHub custom-tools branch | Base: all twelve custom tools, enhanced function matching, server recovery, transport compatibility, and Claude integration. |
| `C:\GHIDRA\GhidrAssistMCP\GhidrAssistMCP` | Recovered uncommitted Manager/Plugin/Provider initialization changes. Its older Server and script runner contain no additional work beyond the published branch. |
| Installed 12.0.2 extension source archive | Confirms the same three local UI changes were shipped. |
| Installed 12.0.3 extension source archive | All Java contents are represented in existing Git history. |
| Documents checkout and Desktop `_RE_Campaigns\_ghidrassist_src` | All Java contents are represented in existing Git history. Root-level duplicate files are not additional sources. |
| Three `AUtomation_IDEAS_OLD` reference/upstream trees | All Java contents are represented in existing Git history; no unique changes recovered. |

Comparison normalizes CRLF/LF before comparing each source file against Java
blobs in the fetched Git history. This avoids treating line-ending changes as
custom implementations. Indexed H: archive paths were not accessible on this
machine during consolidation; their C: archive counterparts were inspected.

Original checkouts and installed extensions were left intact. The task workspace
contains `source-snapshots/inventory.json`, source ZIP snapshots, and binary-safe
Git working-tree patches for provenance and recovery.

## Local UI changes retained

The server manager is registered before constructing the UI provider. Provider
construction occurs during plugin initialization, then the server owner attaches
the provider through `setProvider`. The provider's Window menu group and explicit
visibility setup are retained. This preserves local initialization behavior
without reverting newer transport or custom-tool additions.

The `custom-consolidated` branch records this baseline before upstream migration.

## Upstream integration

The `custom-upstream-2.11` branch merges upstream `0d412d1` (tag `2.11.0`)
on top of that consolidated baseline. Both histories remain intact.

Resolved conflicts:

- Backend: retain upstream registrations and the twelve custom tools; restore
  eight original schema-specific tools that upstream consolidated.
- Function listing: retain glob, regex, prefix, suffix, substring, and case
  options. Match either the plain name or qualified name and display qualified
  names. A plain-name pattern such as `Read*` continues matching `Core::ReadData`.
- README: retain upstream documentation plus the fork's custom-tool documentation.

The seven newer custom tools are `create_memory_block`,
`export_function_signatures`, `function_byte_matcher`, `string_anchor_matcher`,
`bulk_transfer_labels`, `create_functions_at_addresses`, and `bulk_region_transfer`.
The five earlier tools and the March HTTP transport compatibility wrapper remain.

### Legacy API compatibility

| Existing name | Upstream name |
| --- | --- |
| `get_program_info` | `get_binary_info` |
| `list_functions` | `get_functions` |
| `get_function_info` | `analyze_function` |
| `list_segments` | `get_segments` |
| `list_imports` | `get_imports` |
| `list_exports` | `get_exports` |
| `list_strings` | `get_strings` |
| `get_hexdump` | `get_data_at` |
| `list_data` | `get_data_vars` |
| `list_namespaces` | `get_namespaces` |
| `list_programs` | `list_binaries` |
| `class` | `classes` |
| `rename_symbol_batch` | `batch_rename` |
| `list_relocations` | `get_relocations` |

Aliases delegate to the current implementation, including schemas, annotations,
caching, and async execution. Each alias shares its enabled state with its
upstream name, so disabling either disables both. Saved settings under old names
are honored. The UI synchronizes both names after applying changes.

The original `get_data_type`, `delete_data_type`, `list_data_types`,
`set_function_prototype`, `set_local_variable_type`, `set_data_type`, `set_comment`,
and `get_call_graph` implementations remain registered with their original schemas.
Upstream's consolidated tools are also available. Existing Claude integration
can continue using its current names and arguments.

Startup defers server discovery until the owner's provider loads saved tool
settings. New tools inherit backend defaults instead of becoming enabled simply
because no saved preference exists. The upstream headless lab profile also
disables the custom script runner, matching its existing restriction on scripts.

### Validation

Build and tests ran with Temurin JDK 25.0.4.1, the pinned Gradle 9.6.1 wrapper, and
the installed Ghidra 12.0.2 distribution at `C:\GHIDRA\FRESH_GHIDRA`:

```powershell
./gradlew.bat -PGHIDRA_INSTALL_DIR=C:\GHIDRA\FRESH_GHIDRA test buildExtension
```

Set `JAVA_HOME` to a JDK 25+ before running the command. The task's downloaded JDK
is local to its `toolchains` directory; system Java settings were not changed.
The dependency archive was verified against its publisher's SHA-256 checksum.

All 63 tests pass, including upstream regressions, registry/alias compatibility,
and disposable ProgramDB/project integration tests. The extension ZIP is produced
under `dist/`. No extension was installed and no live user program was modified.
GUI initialization and a real shared-repository connection still need a deployment
smoke test; repository API dispatch and preconditions have isolated contract tests.

## Script survey implementation

Three Luna agents surveyed 152 script paths (121 distinct file contents). Generic
operations were integrated into this branch; ECU-specific profiles, A2L/PyCal
parsers and the optional evidence-template importer remain separate scripts.
The task workspace contains the original survey reports under `script-survey/`.

The registry now contains 80 implementations and 14 compatibility aliases: 94
names total. All 49 upstream names are covered by a runtime discovery regression
test generated from upstream commit `0d412d1`. Upstream's disabled-by-default
script/import/export settings remain intact. The latest fetch on 2026-09-11
confirmed that commit is still upstream/master.

| New tool | Purpose |
| --- | --- |
| `query_address_context_batch` | Bytes, function, symbols, data/instruction and incoming references for multiple addresses. |
| `search_symbols_batch` | Exact, substring or glob searches with type/source filters and traversal/output limits. |
| `read_memory_batch` | Bounded reads with explicit endian and signed/unsigned integer decoding; per-row short-read results. |
| `read_memory_table` | Explicit stride, offsets and integer field types; validates widths and duplicate names. |
| `xrefs_batch` | Incoming/outgoing references enriched with endpoint functions and symbols. |
| `function_inventory` | Structured paginated function ranges, bounded entry-byte hashes, counts and optional call edges. |
| `scan_instructions` | Mnemonic/text predicates over bounded half-open address ranges. |
| `scan_function_candidates` | Preview missing functions at instruction/call targets; explicit transactional apply. |
| `get_register_context` | Actual stored value intervals and gaps, including changes inside a requested range. |
| `save_program` | Save an open program database without closing or checking it in. |
| `project_repository` | Ghidra file status/history/checkouts, checkout/add/checkin and undo-checkout with a retained copy. |

Existing tools were extended:

- `project_files`: create folders, copy, move and rename, with dry-run previews,
  collision checks, exact project paths and dirty/busy-file preconditions. It now
  runs through MCP task handling; recursive new operations cap preflight at 10,000
  entries. Folder copy/move is not atomic: inspect the destination after an error.
- `bulk_transfer_labels`: optional comments, bookmarks, existing data types and
  register context with preserve/replace/error policies and structured item results.
  New annotations preview by default. Legacy names still apply unless `dry_run=true`;
  use `preview_annotations=false` to apply annotations. Annotation apply batches
  roll back on error. Data types must already resolve in the target program.
- `set_register_context`: dry-run and structured before/after results; merge and
  set-if-unset respect interior register intervals. Context/scanner ranges use
  `[start,end)`; annotation transfer's explicit register `end` is inclusive.

Memory batch/context requests cap total bytes at 1 MiB. Batch xref budgets cap at
10,000 references, with at most 32 symbols per endpoint and truncation flags.
64-bit typed integers are decimal strings to preserve precision in JSON clients.
Register reads fail explicitly when segment limits would leave an incomplete view.

Mutator annotations were corrected for `write_bytes`, `clear_code_ranges`,
`patch_instruction` and `set_register_context`. Backend context decoration now
preserves errors, structured results, metadata and remaining content blocks.

### Save verification

The persistence integration test creates a fresh temporary Ghidra project, changes
a program property, calls `save_program`, verifies the program remains open and
clean, releases/closes the project, then reopens it from disk and verifies the
stored property. Active-transaction refusal and clean-file no-op are also tested.
This verifies program database persistence; FrontEnd session metadata is a
different operation. Save never performs checkout, checkin or forced unlocking.

### Repository operations

`project_repository` uses the active project's configured Ghidra repository and
permissions, not Git. Add/checkin require a comment. Dirty/busy files are refused,
checkin refuses pending merges, and undo-checkout requires `confirm=true` and
always retains a private copy. Interactive update/merge, force checkout, hijack,
and repository authentication setup are intentionally not automated.
