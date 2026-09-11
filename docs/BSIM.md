# Native Ghidra BSim tools

This fork adds 32 `bsim_` tools using Ghidra 12.0.2's Java BSim APIs. All 94 previously registered names remain available (126 total). No separate Python service or independent SQL schema is introduced.

## Tool groups

| Purpose | Tools (all names begin with `bsim_`) |
| --- | --- |
| Connections | `list_connections`, `configure_connection`, `remove_connection` |
| Database lifecycle | `database_info`, `list_templates`, `create_database`, `update_database`, `drop_database`, `maintain_database` |
| Corpus | `generate_signatures`, `ingest`, `update_metadata`, `remove_executables`, `export`, `rebuild_corpus` |
| Queries | `list_executables`, `list_functions`, `get_function`, `query_functions`, `query_program`, `overview`, `query_vectors` |
| Direct comparisons | `compare_functions`, `match_programs` |
| Reviewed changes | `preview_matches`, `apply_matches` |
| Persistent work | `list_jobs`, `get_job`, `get_results`, `resume_job`, `cancel_job`, `purge_job` |

## Connections and database lifecycle

Use `database` or `profile_id` for a saved profile, or `database_url` for an explicit stock BSim URL. `database` also accepts a URL. Configure profiles with `profile_id` and `database_url`; optional `user` and `keystore` identify an account or existing key store. Passwords, tokens, private keys, and credential-bearing URLs are rejected. Authentication uses Ghidra's normal facilities; headless authentication does not prompt on stdin.

Example tool arguments:

```json
{"profile_id":"research","database_url":"file:/C:/BSim/research"}
```

Pass those arguments to `bsim_configure_connection`. List available templates with `bsim_list_templates`, then create a database:

```json
{"database":"research","template":"medium_32","name":"Research corpus"}
```

`create_database` returns a persistent job. Template IDs may include or omit `.xml`. Existing databases are not adopted by a new create request. `database_info` returns health, layout/version/settings, categories, tags, and the native filter labels accepted by similarity queries. `update_database` edits name/owner/description and installs `category`, `date_column`, and `function_tags` definitions.

`drop_database` and `remove_connection` require `confirm:true`. `remove_executables` previews an exact MD5 or exact name by default; `apply:true` removes only a uniquely resolved executable. Database deletions operate on executables, not individual functions.

| Backend | Create/drop and corpus/query APIs | Index maintenance | Prewarm |
| --- | --- | --- | --- |
| Embedded H2 | Implemented; disposable integration tests pass | Explicitly unsupported | Unsupported |
| PostgreSQL | Implemented through native API; live integration unverified | Drop/rebuild | Supported by native API |
| Elasticsearch | Implemented through native API; live integration unverified | Drop/rebuild | Unsupported |

`maintain_database` changes an index only when `drop_index` or `rebuild_index` is requested, and prewarms only with `prewarm:true`. Rebuilding defaults to dropping the old vector index first. OS services, server users, TLS deployment, physical database backups, and `bsim_ctl` administration are outside these tools.

## Programs, signatures, and ingestion

Program selectors accept open names, exact project paths, or full Ghidra program URLs. Use `project_folder` with optional `project_url` and `recursive` to traverse a local/shared project. Closed source programs are acquired temporarily and released. An absent project view can be opened through Ghidra's URL API. Project/repository permissions still apply.

Long jobs freeze folder selections into exact program URLs before queuing. Saved file IDs, timestamps, versions, executable MD5s, resolved database URLs, and signature configuration identify inputs. Save programs and finish analysis/transactions before starting resumable source-program work.

```json
{"database":"research","project_folder":"/Firmware","recursive":true}
```

Pass this to `bsim_ingest` to generate and insert signatures from the resolved programs. Alternatively, pass `xml_directory` pointing to staged insert XML. `generate_signatures` takes `output_directory` plus a database or `config` template. Optional `addresses` restricts function entry points. `metadata_only:true` produces metadata-update XML. `update_metadata` accepts saved programs or a directory of staged `update_*.xml` files. Database category/date/tag definitions configure native signature generation.

Artifact paths are relative to `<Ghidra user settings>/ghidrassistmcp-bsim/artifacts`; traversal through an outside path/link is rejected. Generated XML is retained for resume. Export requires an executable `md5` or `name` plus `output_file`; it writes ingest-compatible XML, provenance, and a signature-configuration JSON sidecar. The sidecar records public settings and significance normalization, not a physical database backup or a dump of custom internal IDF tables.

`rebuild_corpus` requires a separate `destination_database`. Optional `create_destination:true` and `template` create it. Compatible corpora copy through native XML so source SQL row IDs cannot leak into destination inserts. Incompatible settings require explicit saved `programs` for regeneration with destination settings. The original database remains intact. This operation differs from vector-index rebuilding.

Export/rebuild currently enforce bounds of fewer than 10,000 functions per executable and fewer than 10,000 source executables; exceeding a bound fails rather than silently dropping records. A regeneration rebuild processes the explicitly supplied source programs, so select the complete intended source set.

## Similarity, vectors, and review

`query_program` searches the database for the selected programs' functions. `query_functions` adds exact `addresses`. Set `similarity` (0..1), `significance`, `limit` (matches per source function, maximum 1000), `batch_size`, and optional `exclude_self`. Native query `filters` are objects with `type` and `value`; use labels from `database_info.filter_types`. `overview` reports native vector-match counts.

Executable/function listings accept limits and offsets. Function lookup needs an executable MD5 or name, and `get_function` can disambiguate duplicate function names with a hexadecimal `address`. Use `get_function` to retrieve a stored `vector_id`, then supply string IDs to `query_vectors`; strings preserve all 64 bits. Similarity responses do not always contain a persisted vector ID.

`compare_functions` compares two function addresses in the selected program without a database. `match_programs` compares exactly two selected programs, sharing the same architecture-appropriate weighting configuration. `max_functions` bounds work (default 1000, maximum 10,000 per program); all selected functions are examined within that bound. Results include source/target program URLs and entry points for review.

`preview_matches` accepts explicit target `program`/`address` rows, optional source `source_program`/`source_address`, and transfer flags. It resolves source names/prototypes/comments and persists a preview ID with source/target fingerprints. It does not modify programs.

- `transfer_name` defaults to true.
- `transfer_signature` and `transfer_comments` default to false.
- `overwrite` defaults to false, preserving existing user/imported names, signatures, and comments.

`apply_matches` requires `preview_id`, distinct integer `selected` row indices, and `confirm:true`. A target function may receive only one selected match. Stale source/target previews are rejected. Signature transfer uses Ghidra's native function/type application, not a comment containing a prototype. Each target program has one transaction: any error/cancellation rolls back its selected changes. Programs already committed before another target fails remain changed; inspect per-target results.

Previously closed writable targets are handed to CodeBrowser before mutation so unsaved changes retain an owner. Read-only views must be opened writable/checked out first. Applying matches does not save or check in programs; use the separately verified `save_program` tool after reviewing changes. Full prototypes/types require access to the original Ghidra source program; BSim records alone do not contain them.

## Persistent jobs and results

Long operations return `job_id` immediately. These IDs are separate from the older transient `get_task_status` task IDs. Use:

```json
{"job_id":"<returned UUID>"}
```

with `bsim_get_job`, then retrieve results:

```json
{"job_id":"<returned UUID>","field":"results","offset":0,"limit":100}
```

`field` is optional; corpus operations commonly return `files` instead of `results`. Default result pages are 100, maximum 1000. Synchronous calls accept `result_limit`. Completed result arrays are stored as JSON lines and paged from disk. Active/interrupted jobs expose completed unit checkpoints. Query execution still holds its accumulated result rows in memory before final serialization; paging does not imply an unlimited-memory workload.

Journals and unit results live under `<Ghidra user settings>/ghidrassistmcp-bsim/jobs/<UUID>`. Restart marks running/queued jobs interrupted and never executes them automatically. `resume_job` is explicit. Completed units are validated/skipped; uncertain inserts reconcile exact executable identities and function counts; changed staged XML is rejected. Pending create operations that cannot be reconciled fail with an actionable error rather than blindly repeating creation.

Cancellation is cooperative; an in-flight native database request must settle before work stops. `purge_job` requires `confirm:true`, refuses active jobs, and removes journal/results only. Exported/generated corpus artifacts remain for explicit separate cleanup. Profiles never contain database credentials.

## Verification

The automated suite covers all previous upstream/custom endpoint names, real H2 create/update/drop, metadata/category/date/tag definitions, real decompiler signatures and comparisons, ingestion/query/vector lookup, XML export/re-import, separate corpus rebuild, exact deletion preview/apply, uncertain-insert reconciliation, changed-XML rejection, source/target stale previews, group rollback, native signature transfer, closed-project reopening, async job failure/completion, restart recovery, pagination, and credential rejection.

The optional PostgreSQL/Elasticsearch lifecycle tests require `BSIM_RUN_EXTERNAL_TESTS=1` and explicit disposable `BSIM_TEST_POSTGRES_URL` / `BSIM_TEST_ELASTIC_URL`. They create and drop those named databases. They were not executed on this host: Docker is not responding and WSL reports `HCS_E_HYPERV_NOT_INSTALLED`. Shared-server authentication, remote permission edge cases, and native remote maintenance therefore remain unverified in a live deployment.

Build with JDK 25 and Ghidra 12.0.2:

```powershell
.\gradlew.bat '-PGHIDRA_INSTALL_DIR=C:\GHIDRA\FRESH_GHIDRA' test buildExtension --console=plain
```

Official background: [Ghidra BSim tutorial](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Intro.html) and the installed Ghidra BSim Java sources. This implementation uses those stock APIs directly.
