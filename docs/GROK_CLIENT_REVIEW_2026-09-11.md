# Grok client review of new GhidrAssistMCP tools

Reviewed 2026-09-11 against the current tree, the live `ghidra-assist` MCP session, and Grok TUI client behavior. This records whether Grok needs its own integration package now that Codex, Claude, native VT/BSim, batch queries, and task waiting have landed. It is not an implementation, an installed-client change, or a claim that every new tool was executed end to end.

Related documents: [Claude vs Grok client compare](CLIENT_INTEGRATION_COMPARE_2026-09-11.md), [Claude Code integration ideas](CLAUDE_INTEGRATION_IDEAS_2026-09-11.md), [Codex integration](CODEX_INTEGRATION.md), [Codex review](CODEX_REVIEW_2026-09-11.md), [modernization](MODERNIZATION_2026-09-11.md), [tool catalog](TOOL_CATALOG_AUDIT.md), [VT](VT.md), [BSim](BSIM.md), [native analysis](NATIVE_ANALYSIS.md), [project workflows](WORKFLOWS.md), [Grok product repairs](GROK_REPAIR_AND_INSTALL_2026-09-11.md). The product-repair documents cover Java defects found by a Grok source review. This document covers Grok **as an MCP client**.

## Verdict

Grok-specific enhancements are needed. The server work is largely client-neutral and already live. Grok still uses a Codex-shaped skill, has no project MCP config, and a 20 KiB result cap that already truncates the documented first call (`runtime_capabilities`) when many programs are open.

Do not copy the Codex 27-tool allowlist into Grok. Grok discovers tools with `search_tool` rather than stuffing the catalog into context. Port the workflow, raise the byte budget, and teach the new families. Do not add Grok-only Java, OAuth, or ACP runtime code to this extension.

## Method and live evidence

Source of the live snapshot:

- Grok TUI session with `ghidra-assist` connected at `http://localhost:8080/mcp`
- `ghidra-assist__runtime_capabilities` with no selector
- `search_tool` queries for BSim, VT, native analysis, and project tools
- Repository integrations: `.agents/skills/ghidrassist-mcp`, `codex-integration/`, `claude-code-integration/`
- Grok user guide: MCP servers, skills, hooks, config reference
- User config `~/.grok/config.toml`: `[mcp_servers.ghidra-assist]`, `permission_mode = "always-approve"`, no `[mcp] max_output_bytes` override

Live `runtime_capabilities` reported:

| Field | Value |
| --- | --- |
| Ghidra | 12.0.3, GUI, not headless |
| Tools | 145 registered, 142 enabled |
| Protocol | through `2025-11-25`; `stateless_2026_07_28=false`; `tasks_extension=false` |
| Application task API | `wait_task`, `get_task_status`, `list_tasks`, `cancel_task` |
| Native VT | available; correlators include exact/similar function and data matchers plus BSim function matching |
| BSim | `api_available=true`; backend health not probed |
| Open programs | 32, with duplicate display names (`etas-j1850.ko`, `libbvtx-vci-pdu.so.1.0.0.0`, `repro_service`) |
| Active window | `app_service` (can change between calls) |

The same capabilities call was truncated by Grok at about **19.5 KiB of ~20.5 KiB**. The inline payload stopped inside the open-program list. Native VT, BSim, and task-recovery fields were only visible in the session spill file:

`C:\Users\JResp\.grok\sessions\...\mcp\call-aa4440cd-2b04-4ddb-9b43-4d9a05c8026a-44.txt`

That is the documented first Grok/Codex call overflowing Grok's default MCP output cap.

## New tool families Grok must be able to use

These are the additions since the older analysis/patch/export set. Public names are from the [catalog audit](TOOL_CATALOG_AUDIT.md). Disabled defaults remain `export_program`, `import_file`, and `scripts`.

| Family | Representative tools | Agent contract |
| --- | --- | --- |
| Discovery | `runtime_capabilities`, `list_binaries` | Build identity, protocol limits, exact `program_id`. Capabilities currently dumps every open program. |
| Generic tasks | `wait_task`, `get_task_status`, `list_tasks`, `cancel_task` | Bounded wait (max 30s). Timeout does not cancel work. In-memory; lost on JVM restart. Not the MCP Tasks extension. |
| Bounded search | `search_functions_by_name`, `search_strings` | `has_more` / `next_offset`; restart if the program revision changes. |
| Batch / inventory | `query_address_context_batch`, `search_symbols_batch`, `read_memory_batch`, `read_memory_table`, `xrefs_batch`, `function_inventory` | Structured rows, per-row errors, short reads, `scan_truncated` / `total_matched_is_exact`. |
| Native analysis | `datatype_archive_catalog`, `parse_c_declarations`, `datatype_import_selected`, `program_diff`, `fid_list_databases`, `fid_identify_functions` | Preview tokens; parse stages a GDT and does not mutate the program; FID does not apply labels. |
| Version Tracking | `vt_sessions`, `vt_session`, `vt_correlators`, `vt_correlate`, `vt_matches`, `vt_review_matches`, `vt_add_matches`, `vt_markup`, `vt_apply_markup`, `vt_unapply_markup` | Session save ≠ program save. Apply requires accepted matches and a fresh preview token. |
| BSim | 32 `bsim_*` tools | Durable jobs: `bsim_get_job` / `bsim_get_results` / `bsim_resume_job`. Do not use `wait_task` for these. |
| Project / persistence | `save_program`, `save_project_session`, `project_files`, `project_repository`, `open_program`, `close_program` | Distinct save domains. Delete/check-in require `confirm` / comments. |
| Compare / transfer | `function_byte_matcher`, `string_anchor_matcher`, `export_function_signatures`, `bulk_transfer_labels`, `bulk_region_transfer` | Cross-program matching; prefer these over ad-hoc hexdump/`search_bytes` pipelines. |

Twelve descriptors currently declare output schemas. The other 133 keep established text/JSON fallbacks. Grok should prefer structured fields when present and must not treat truncated text as a complete result.

## Client comparison

| Capability | Codex | Claude Code | Grok TUI (this session) |
| --- | --- | --- | --- |
| Transport | Streamable HTTP `/mcp` | MCP tools via Claude naming | Streamable HTTP `/mcp` as `ghidra-assist` |
| Catalog control | `enabled_tools` allowlist (27-tool example) | Full server catalog | `disabled_mcp_tools` denylist only |
| Discovery | Tools injected into context | Tools injected into context | `search_tool` then `use_tool`; default 5 hits |
| Output budget | Per-tool token limits (example 24k on `get_code`) | Claude tool-result limits | **20,000 bytes** default; spill file under session `mcp/` |
| Tool timeout | Example 75s (Codex default ~60s) | Claude defaults | Default **6000s**; `wait_task` 30s is not a problem |
| Skill | `.agents/skills/ghidrassist-mcp` | `claude-code-integration/skills/ghidra-function-port` plus rename hooks | Same Codex skill; no Grok section; Claude skill not on a Grok path |
| Resources / prompts | Documented for Codex | Claude resource/prompt support varies | **Not exposed.** No `resources/read` or `prompts/get` in this client |
| Integration package | `docs/CODEX_INTEGRATION.md`, `codex-integration/config.example.toml` | `claude-code-integration/` | **None.** No `grok-integration/`, no project `.grok/config.toml` |
| Approval | Client allow/deny | Hooks on `rename_symbol` | User `permission_mode = "always-approve"` |

Server instructions advertised at initialize are client-neutral and already correct: start with `runtime_capabilities` and `list_binaries`, use exact `program_id`, page results, follow `task_id` with `wait_task`, and treat application task IDs as distinct from MCP Tasks. Grok does not currently surface those initialize instructions as strongly as a dedicated skill.

## What already works for Grok

- Native HTTP MCP to loopback does not send a browser `Origin`; the server's Origin filter accepts that.
- `search_tool` finds the new families when the query names them (`bsim_`, `vt_`, `datatype_archive`, `project_files`).
- Default Grok tool timeout is far above `wait_task`'s 30 second ceiling.
- The existing skill is correct on exact `program_id`, paging, generic task recovery, and `save_program` versus VT/BSim session saves.
- Core protocol improvements (schemas, `wait_task`, resource templates, JSON text fallback) remain client-neutral. They should stay that way.

## Findings

### 1. Default 20 KiB cap truncates discovery

Grok user-guide default: `[mcp] max_output_bytes = 20000`, overridable by env or project `.grok/config.toml`. This session has no override.

`runtime_capabilities` with 32 open programs produced a context banner plus a JSON object that included every program's `program_id`, path, and URL. Grok truncated the inline result mid-object. `list_binaries`, `get_code`, `function_inventory`, and `get_task_status` will hit the same limit.

The spill file preserves the rest, but the current skill does not say to open it, and a chopped JSON object is not a structured result.

### 2. Skill coverage stops before the new families

[`.agents/skills/ghidrassist-mcp/SKILL.md`](../.agents/skills/ghidrassist-mcp/SKILL.md) covers capabilities, `program_id`, two searches, batch queries, `function_inventory`, and generic `wait_task`. It does not teach:

- Grok `search_tool` → `use_tool`, or that the default hit count is 5 among 142 enabled tools
- BSim durable jobs versus generic `wait_task`
- VT session / correlate / review / markup and preview tokens
- Native GDT/C/FID staging versus apply
- Using `list_binaries` instead of a truncated capabilities dump
- Offline `ghidra-reader` versus live `ghidra-assist`
- Name collisions: Grok `grok_wait`, Ghidra `wait_task`, and the separate `tasks` MCP server
- Duplicate display names requiring `program_id`

It also tells the client to use `ghidra://` resource URIs. This Grok client has no resource reader.

### 3. Codex allowlist is the wrong Grok default

`codex-integration/config.example.toml` intentionally omits VT, BSim, type-editing, and project-administration tools. Codex can restore them with `enabled_tools`. Grok cannot express an allowlist; it can only deny tools.

Copying that 27-name list into Grok would hide the families this review is about. Keep the full catalog visible and teach family search queries.

### 4. Always-approve plus enabled destructive tools

This user's Grok config auto-approves tool calls. The server enables `clear_code_ranges`, `patch_bytes`, `write_bytes`, `project_files` delete, `bsim_drop_database`, `bsim_apply_matches`, and VT markup by default. Claude's `rename_symbol` hooks are not loaded as Grok hooks.

A Grok PreToolUse hook or a skill hard-stop on `confirm=true` / preview-token mutations is more important here than on Codex.

### 5. Claude function-port skill is not Grok-ready

`claude-code-integration/skills/ghidra-function-port` uses Claude tool names (`mcp__ghidra__list_functions`) and lives under `claude-code-integration/skills/`, which Grok does not scan unless copied. It still drives matching with hexdump/`search_bytes` rather than `function_byte_matcher`, `string_anchor_matcher`, or `bulk_transfer_labels`.

### 6. Server compactness would help Grok without being Grok-only

Grok's byte cap is stricter than Codex's token cap. These server changes would help any small-budget client:

- Summarize open programs in `runtime_capabilities` (count, active program, name collisions). Leave the full inventory to `list_binaries`.
- Prefer a short text digest when `structuredContent` is present. Repeating the full JSON in the text channel doubles Grok's byte use.
- Optional `include_programs=false` (or equivalent) on capabilities so the documented first call stays inside a 20 KiB budget.

Do not remove the JSON text fallback for text-only clients. Do not add a Grok-only protocol.

### 7. Out of scope for this client package

- MCP Tasks extension (neither Grok nor this server negotiates it)
- July 2026 stateless protocol
- Raising Grok's already-large tool timeout
- Transplanting Grok ACP, OAuth, or named-pipe runtime into the Ghidra JVM ([Codex review](CODEX_REVIEW_2026-09-11.md) already rejected that)

## Recommended work

Not implemented by this document.

| Priority | Work | Why |
| --- | --- | --- |
| P0 | Project `.grok/config.toml` and `grok-integration/config.example.toml` with `[mcp] max_output_bytes` at least 64–128 KiB | Live capabilities already overflows 20 KiB |
| P0 | Expand `.agents/skills/ghidrassist-mcp/SKILL.md` with a Grok section | Search/use flow, truncation/spill recovery, BSim vs `wait_task`, VT/native preview tokens, `program_id` collisions, no resource/prompt client |
| P0 | `docs/GROK_INTEGRATION.md` parallel to the Codex guide | Connection, budgets, family map, recovery |
| P1 | Compact `runtime_capabilities` program listing | Makes the documented first call reliable for every small-budget client |
| P2 | Grok hook on mutating `confirm` / `preview_token` tools | This session auto-approves |
| P2 | Grok-adapted function-port skill using `ghidra-assist__*` names and the matcher/transfer tools | Claude skill is undiscoverable and outdated |

Suggested Grok config shape (example only; not checked in here):

```toml
[mcp]
max_output_bytes = 131072

[mcp_servers.ghidra-assist]
url = "http://127.0.0.1:8080/mcp"
enabled = true
tool_timeout_sec = 120
tool_timeouts = { wait_task = 35, get_code = 120, analyze_program = 300 }
```

Do not add `enabled_tools`. Optional denylist only for tools this deployment must never call.

## Skill family search map

Use these `search_tool` queries from Grok rather than hoping the default top-5 contains the right name.

| Intent | Query | Then call |
| --- | --- | --- |
| Connect / select program | `ghidra-assist runtime_capabilities list_binaries` | exact `program_id` on later calls |
| Find code | `search_functions_by_name get_code function_inventory` | page with `next_offset` |
| Related addresses | `query_address_context_batch xrefs_batch read_memory_batch` | inspect `partial` / per-row errors |
| Long generic work | `wait_task get_task_status cancel_task` | `timeout_ms` waits only |
| BSim | `bsim_list_jobs bsim_get_job bsim_query_program` | durable `job_id`, not `wait_task` |
| Version Tracking | `vt_session vt_correlate vt_markup` | preview token before apply |
| Types / headers | `parse_c_declarations datatype_import_selected fid_identify` | dry-run then token |
| Persist | `save_program save_project_session vt_session` | inspect each save result |
| Port annotations | `function_byte_matcher bulk_transfer_labels` | then `save_program` |

If a `use_tool` result says it was truncated, read the session spill file under `mcp/`. Do not invent the missing JSON.

## Limits of this review

- One live GUI session with 32 open programs in a Ford VCM3 project. Headless was not re-tested from Grok.
- New families were discovered and schema-inspected; VT/BSim/native apply paths were not executed against user databases.
- Grok TUI resource/prompt support is inferred from the user guide and the tools actually exposed to this session (`search_tool` / `use_tool` only).
- The running JVM advertised a dirty build on top of `5b3a058` while git HEAD is the later modernization commit. The live catalog still showed 145 names, `wait_task`, VT, and BSim, which is the surface Grok has to use.
