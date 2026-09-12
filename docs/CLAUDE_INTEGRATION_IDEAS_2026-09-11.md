# Claude Code integration — ideas and direction (September 11, 2026)

Brainstorm record, not an approved design. Captures the current state of the
Claude Code integration, verified client constraints, decisions made so far,
and the candidate approaches. A design spec follows once an approach is chosen.

## Where the integration stands after the modernization

Server side (see [modernization report](MODERNIZATION_2026-09-11.md)):

- MCP Java SDK 2.0.1, Jetty 12.1, protocol revisions through 2025-11-25,
  Streamable HTTP at `/mcp`.
- 145 registered tools, 142 enabled, 14 aliases. 12 tools declare output
  schemas; the other 133 return prose or loosely shaped JSON text.
- 7 prompts (`analyze_function`, `compare_functions`, `document_function`,
  `identify_vulnerability`, `reverse_engineer_struct`, `trace_data_flow`,
  `trace_network_data`). All are static Markdown builders: they take a
  function name, decompile it, list callers/callees, and append a checklist.
  None use exact program identity, batch tools, or the task lifecycle.
- 6 program resource templates plus the concrete runtime capabilities
  resource. Subscriptions and list-changed are not advertised.
- Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`) are emitted for every tool from `McpTool` defaults.

Claude Code side:

- The installed plugin `ghidrassist@custom-plugins` is a single `.mcp.json`
  pointing at `http://localhost:8080/mcp`. No skills, agents, or commands.
  Tool prefix in Claude Code is `mcp__plugin_ghidrassist_ghidrassist__`.
- `claude-code-integration/` in the repo is a one-off from the Bosch 0762
  porting work: one skill hard-wired to specific program names and PowerPC
  VLE byte rules, two hooks whose matcher (`mcp__ghidra__rename_symbol`)
  does not match this plugin's tool names, and three Ghidra scripts.
- Codex got a repository skill, a curated 27-tool profile, and per-tool output
  budgets. Claude Code got none of the equivalent.

## Verified Claude Code client constraints

Checked against current Claude Code documentation on 2026-09-11.

| Feature | Claude Code CLI | Consequence for this project |
| --- | --- | --- |
| Tools | Supported | Baseline. |
| Prompts | Supported, exposed as slash commands `/mcp__<server>__<prompt>` | Server prompts are the natural workflow entry points. |
| Resources | Referenced by `@` mention; list/read tools exist in the client | Keep the templates; low priority. |
| Elicitation | Not supported | No confirm-before-mutate on the server. Safety stays with Claude Code permission prompts and existing server guards. |
| Sampling, logging, progress notifications | Not supported / not surfaced | Do not build on them. |
| Structured output / `outputSchema` | Not consumed by the client | Still useful: the JSON text fallback is what Claude reads, and a schema makes that text predictable. |
| Tool annotations | Hints only; do not change permission prompting | Keep them accurate, expect no behavioral change. |
| Many tools | Schemas are deferred automatically above a token threshold; Claude gets a tool-search tool | No curated profile needed. Tool names and descriptions are now the search surface. |
| `.mcp.json` tool allowlist | Ignored (client bug, issue 20617) | Client-side filtering is not available. |
| Result size | 25k tokens default per result, then spilled to a file; per-tool `anthropic/maxResultSizeChars` annotation can raise it | Large-output tools should declare a budget or page. |

## Decisions so far

1. Scope is (1) Claude Code as a first-class client and (2) server-side MCP
   features aimed at Claude. Claude-inside-Ghidra (the extension calling the
   Claude API itself) is out.
2. Workflow priority: cross-binary porting first, deep single-function work
   second, project operations third. Generic triage is excluded.
3. Hooks and unattended/autonomous run features are out. No PreToolUse or
   PostToolUse hooks, no batch-mode switches.

## Candidate approaches

### A. Plugin-first, light server touch

- Restructure `claude-code-integration/` into a real plugin directory:
  `.claude-plugin/plugin.json`, `.mcp.json`, `skills/`.
- Four skills: core operating guide (Claude-flavored port of the `.agents`
  Codex skill), function porting (generalized from the 0762 skill: byte
  matcher, string anchors, BSim, Version Tracking, then transfer), deep
  function work (decompile, retype, structs, data flow, document), project
  operations (headless, save, check-in, task monitoring).
- `marketplace.json` at the repo root so the plugin installs from the repo.
- Server work limited to rewriting the 7 prompts as workflow entry points
  that take exact program ids.
- Cost: lowest. Risk: the porting skill must parse prose from
  `function_byte_matcher` and `string_anchor_matcher`, which is where the
  old skill spent most of its effort.

### B. Plugin plus targeted server contracts (recommended)

Everything in A, plus:

- Structured output with declared schemas on the tools the skills use to
  make decisions: `function_byte_matcher`, `string_anchor_matcher`,
  `bulk_transfer_labels`, `bulk_region_transfer`, and the VT match listing.
  Follow the existing pattern from the 12 schema-bearing tools and the
  `McpResultContent` JSON fallback.
- Result-size annotations on large-output tools (`get_code`, `get_hexdump`,
  `read_memory_table`, `get_call_graph`) or explicit paging where missing.
- Description tuning across the catalog so deferred-tool search lands on the
  right tool: lead with the verb and object, name the program selector,
  state the output shape.
- Prompts rebuilt around batch tools and exact program identity, with
  arguments for `program_id` and source/target pairs where a workflow spans
  two programs.
- Cost: moderate. Changes stay inside the tool families the workflows use.

### C. Server-heavy

B plus output schemas across all 145 tools and a server-side client profile
that filters the catalog per connecting client. Automatic schema deferral
removes most of the motivation; effort is large.

## Ideas parked for later

- Prompt argument completion (`completion/complete`) so slash-command
  arguments offer open program names. Client support unverified.
- Resource subscriptions for program change notifications. Not consumed by
  Claude Code today.
- A restricted-tool subagent for porting runs. Excluded with the autonomous
  features; revisit if the workflow proves stable.
- A shared skill core between the Codex `.agents` skill and the Claude plugin
  skill, generated from one source so the two do not drift.
- Retiring the 0762-specific scripts in `claude-code-integration/scripts/`
  now that `create_function`, `disassemble_at`, and `create_memory_block`
  exist as tools.

## Related documents

- [Claude vs Grok client compare](CLIENT_INTEGRATION_COMPARE_2026-09-11.md)
- [Grok client review](GROK_CLIENT_REVIEW_2026-09-11.md)
- [Modernization report](MODERNIZATION_2026-09-11.md)
- [Tool catalog audit](TOOL_CATALOG_AUDIT.md)
- [Codex integration](CODEX_INTEGRATION.md)
- [Deployment policy](DEPLOYMENT_TRUST.md)

## Panel review (multi-agent, 2026-09-11)

Six reviewers (plugin author, MCP architect, porting re-review, deep-function re-review, discoverability, skeptic, blind spots) produced 65 items scored by three judges. This section merges them. Item numbers in brackets refer to the panel ledger. Every live observation was taken against the running GUI server with 32 open programs (ARM:LE:32:v8 and x86:LE:32 only).

### Corrections to the document

1. Constraint table row "Elicitation: Not supported" (line 46) is wrong. The current Claude Code MCP page has a section "Respond to MCP elicitation requests" and states "A call waiting on an open elicitation dialog isn't backgrounded while the dialog is open." Change the row to "Supported by the client; not adopted here." The no-confirm-before-mutate decision still stands on its own merits because `dry_run` and `preview_annotations` already exist in `BulkTransferLabelsTool.java:78-80,133-137`. Evidence: https://code.claude.com/docs/en/mcp. [7], [53]
2. Constraint table row "Tool annotations: hints only; do not change permission prompting" (line 49) is incomplete. `_meta["anthropic/requiresUserInteraction"]: true` on a tool forces a permission prompt on every call in acceptEdits, auto, and bypassPermissions modes with no "don't ask again" option. This is a server-side, non-autonomous safety lever within scope. Evidence: same doc URL; SDK 2.0.1 `McpSchema.Tool.Builder.meta(Map)` confirmed by javap. [7]
3. Constraint table row "Result size" (line 52) and approach B (line 91) call `anthropic/maxResultSizeChars` an annotation. It is a tools/list `_meta` entry, not `annotations`, which changes the Java (`descriptor.meta(...)` in `GhidrAssistMCPBackend.java:390-397`, which today sets only name/title/description/inputSchema/annotations/outputSchema). Nothing in `src/main/java` emits `_meta` today (grep for `maxResultSizeChars` and `anthropic/` returns nothing). [10], [37]
4. Constraint table row "Resources" (line 45) is wrong for templates. Claude Code lists resources with `resources/list`, not `resources/templates/list`. Live `ListMcpResourcesTool` on the server returned exactly one resource, `ghidra://runtime/capabilities`. The six templates in `src/main/java/ghidrassistmcp/resources/{ProgramInfo,FunctionList,Imports,Exports,Segments,Strings}Resource.java` are invisible to the `@` picker. [58]
5. Approach B (lines 86-88) lists `bulk_transfer_labels` and `bulk_region_transfer` as needing structured output. Both already call `.structuredContent(Map.of(...))` (`BulkTransferLabelsTool.java:269-272`, `BulkRegionTransferTool.java:655-663`) and only lack `getOutputSchema()`. Because the schema is missing, `McpOutputSchemas.validateCompletion` (`McpOutputSchemas.java:56`) never validates them and `McpResultContent.withJsonFallback` (`McpResultContent.java:36`) appends the serialized JSON as a second text block, so Claude receives the prose report and the full JSON. The same state applies to `create_functions_at_addresses`, `save_program`, `vt/VTSupport.java`, `bsim/BsimSupport.java`, and `nativeapi/NativeAnalysisTools.java`. The two matchers are the real work: `FunctionByteMatcherTool.java:160-191` is prose only and `StringAnchorMatcherTool.java:134-166` hand-concatenates a JSON array after a prose header with `truncate(...,60)` at line 156. [4], [11], [12], [49]
6. Approach B (lines 91-92) names the alias `get_hexdump` instead of the canonical `get_data_at` (`GhidrAssistMCPBackend.java:329` `registerAlias("get_hexdump", "get_data_at")`), lists `get_call_graph`, which is already bounded by `max_nodes` plus `BoundedQueryText` with explicit truncation (`GetCallGraphTool.java:18-33`), and omits the tools that are actually unbounded: `get_basic_blocks` (no limit parameter, raw StringBuilder, `GetBasicBlocksTool.java:68`), `get_data_vars`/`get_imports`/`get_segments` (unclamped `limit`, `ListDataTool.java:55-60`, `ListImportsTool.java:62-67`, `ListSegmentsTool.java:51-56`). Corrected list: `get_data_at`, `get_code`, `get_basic_blocks`, `read_memory_table`, `get_data_vars`, `function_inventory`. [45], [44]
7. Approach A (line 75) says "marketplace.json at the repo root". Claude Code reads only `.claude-plugin/marketplace.json`, with plugin `source` paths resolved relative to the directory containing `.claude-plugin/`. The repo root has no `.claude-plugin/` today. Evidence: https://code.claude.com/docs/en/plugin-marketplaces. [5], [52]
8. Approach B (lines 76-77, 96-98) treats the prompt rebuild as a Markdown rewrite. It is an interface change: `McpPrompt.generatePrompt(Map<String,String>, Program)` receives one Program, and `GhidrAssistMCPServer.java:318` wraps it in `withProgramRequest(...)`, which `GhidrAssistMCPBackend.java:127-128` resolves with `getCurrentProgram()` only. No file under `prompts/` mentions `program_name` or `program_id`. Separately, program_ids cannot be slash-command arguments: Claude Code splits prompt arguments on whitespace and the live program_ids contain a space (`.../Reverse Engineering/SERVER_REPO/...`). [15], [29], [8]
9. Approach A risk statement (lines 78-80) misstates history. The 0762 skill never called `function_byte_matcher` or `string_anchor_matcher`; it hand-built masks with `get_hexdump` and `search_bytes` (`claude-code-integration/skills/ghidra-function-port/SKILL.md` steps 3-4, lines 60-83). [48]
10. The document (line 71) treats `function_byte_matcher` as the generic first-stage matcher. Its masking is PowerPC-VLE specific: `FunctionByteMatcherTool.applyMask` (lines 194-235) decides 32-bit VLE forms from `(bytes[i] & 0x10) != 0 || majorOp >= 0x18` and masks bytes 2-3 of each word; `BulkRegionTransferTool.detectOffset`/`computeOpcodeMatch` use `mask[i] = (i % 4 < 2) ? 0xFF : 0`. Neither file calls `program.getLanguage()`. Every program on the live server is ARM LE or x86, where this masks the wrong half of the word or the ARM opcode itself. [19], [48]
11. `list_binaries`, the tool the server instructions say to call first, contradicts them. Its description says "use the program_name parameter with the listed Project Path" and the live footer repeats it (`ListProgramsTool.java:34-35, 100-103`), while the instructions and every `program_name` schema property (`GhidrAssistMCPBackend.java:~413`) say to use `program_id`. The Codex skill (`.agents/skills/ghidrassist-mcp/SKILL.md` paragraph 2) also says `program_id`. [13], [39], [57]
12. Repo `CLAUDE.md` is stale and will steer server work wrong: it states SDK 0.9.0, Jetty 11, endpoints `/mcp/sse` and `/mcp/message`, 39 tools, and "no formal test suite", while live `runtime_capabilities` reports SDK 2.0.1, Streamable HTTP at `/mcp`, 145 registered tools, and `src/test/java/ghidrassistmcp/` already holds JUnit tests. `README.md` has no Claude Code install section. [60], [64], [46]

### Overlooked, high value

Ordered by panel score. Effort: S small, M medium.

1. (15) Fix architecture-specific masking in `function_byte_matcher` and `bulk_region_transfer`. Derive masks from Ghidra's instruction and operand model (`Instruction.getPrototype()` operand masks, as the VT "Exact Function Instructions Match" correlator does) so PPC-VLE, ARM/Thumb and x86 all work. Until then the skill must say `mask_mode=auto` is trustworthy only on PowerPC VLE. Evidence: `FunctionByteMatcherTool.java:194-267`, `BulkRegionTransferTool.java` detectOffset/computeOpcodeMatch; live `list_binaries` zero PowerPC. M, server. [19]
2. (15) Make `isLongRunning` action-aware or add an inline grace wait. `GetCodeTool.java:42-45`, `VariablesTool.java:50`, `StructTool.java:131-134` return `isLongRunning()=true` for every action; `GhidrAssistMCPBackend.java:519-521` routes them to `executeToolAsync` unconditionally; `WaitTaskTool.java:21` never returns the payload. Live: `get_code` on a 96-byte function returned `{"task_id":...,"status":"RUNNING"}`. Every decompile is three round trips. Fix: per-action `isLongRunning`, or wait up to ~5 s inline before falling back to a task id, and let `wait_task` include the result at terminal state. Claude Code already auto-backgrounds calls over two minutes, so server-side async is redundant for short work. M, server. [30]
3. (14) `bulk_transfer_labels` dry_run must validate prototypes and must not overwrite user names. `BulkTransferLabelsTool.java:189-214` applies the prototype only inside `if (!dryRun && !sameName)` and calls `func.setName(name, SourceType.IMPORTED)` whenever the name differs, replacing USER_DEFINED names; `conflict_policy` governs only comments/bookmarks/data_types/register_context. Port the BSim contract: `BsimMatchOperations.java:284` renames only when `overwrite || source == DEFAULT`, and its preview rows carry beforeName/beforePrototype/namePreserved/conflict plus a programFingerprint stale check (lines 78-87, 135-141). Add `current_name`, `current_name_source`, `prototype_parse_ok` to dry-run items and a `name_policy {default_only|replace}` argument. S, server. [22]
4. (13) `vt_matches` needs names, filters and sort. `VTSupport.java:111-113` emits only set id, addresses, lengths, type, status, similarity, confidence; `VTTool.java:145-149` pages all match sets linearly (max 500) with no status/min_similarity/match_set_id/range filter. Add `source_name`, `destination_name`, `destination_name_source`, `status`/`min_similarity` filters and score sort; note in the skill that duplicate-* correlator sets must be disambiguated, not accepted. Native VT is the only architecture-correct matcher installed (14 correlators live) and its accept/reject status is a durable ledger. S, server. [23]
5. (13) Live blocker: every call carrying `program_id` or `program_name` hangs. Direct curl: `get_binary_info {}` returned in 0.275 s; with `program_name` (name or project path) it timed out at 60 s; through Claude Code the same happened with an exact `program_id` for `get_binary_info`, `get_functions`, `search_functions_by_name`, `function_byte_matcher`, `function_inventory`, and `ReadMcpResourceTool` on `ghidra://program/...`. Resolution path: `GhidrAssistMCPBackend.resolveTargetProgram` (line 791) to `ProgramIdentity.resolve`; suspect `file.getSharedProjectURL(null)` at `ProgramIdentity.java:19,37,57` blocking on an OneDrive-rooted project. Related: `GhidrAssistMCPManager.getAllOpenPrograms` (lines 236-250) dedupes by Program instance, so `repro_service` appears twice with identical program_id and file_id `645eb549ece0118342950581300`; dedupe by file_id+version. Add a scripted conformance run (initialize, list_binaries, one call per selector kind, one resource read, one paged query) recorded in `docs/REVIEW_VALIDATION.md` style; existing tests run only against disposable `ProgramDB`. M, server plus process. [56], [47], [14], [59]
6. (12) Skill descriptions as trigger phrases plus exclusions. Claude Code auto-invokes from `description` plus `when_to_use`, truncated at 1,536 characters combined. The Codex description (`.agents/skills/ghidrassist-mcp/SKILL.md:3`) names no user phrases; the 0762 description (`claude-code-integration/skills/ghidra-function-port/SKILL.md:3, 12-22`) is the right shape. Add `when_to_use` with 3-4 literal requests and `argument-hint: [source-program] [target-program]`. Evidence: https://code.claude.com/docs/en/skills. S, plugin. [2]
7. (12) Emit `anthropic/maxResultSizeChars` via Tool `_meta` and lower defaults. `GetCodeTool.java:91,114` default and max `max_chars` are 200,000 (~50k tokens, twice the 25k-token spill); `BoundedQueryText.java:5` `MAX_CHARS=200_000` is the universal budget; `GetHexdumpTool.java:66` allows `len` up to 65,536 (~315k chars of hexdump, no cursor); `BatchQuerySupport.java:13` allows 1000 rows x 64 fields. Add `default Map<String,Object> getToolMeta()` to `McpTool`, set it on `get_code`, `get_data_at`, `get_basic_blocks`, `read_memory_table`, `function_inventory`, drop `get_code` default to ~60-90k chars, route `get_data_at` and `get_basic_blocks` through `BoundedQueryText`, clamp `limit` via `QueryPageBounds` in the three list tools. Note Codex caps `get_code` at 24,000 output tokens client-side (`codex-integration/config.example.toml`); Claude Code has no client-side cap, so the server default is the only lever. S/M, server. [10], [44], [37], [62]
8. (12) Prompt and skill arguments take project paths, resolved once to `program_id`. Live: three display names appear twice (`libbvtx-vci-pdu.so.1.0.0.0`, `libbvtx-vci-rt-p.so.1.0.0.0`, `etas-j1850.ko`, also `etas-prot-driver.ko`) across VCM2_SO and VCM3_* folders, so name selectors are ambiguous by construction for the exact porting pairs; `ProgramIdentity.resolve` (line 46) throws "Ambiguous program selector". Project paths are unique and whitespace-free; program_ids are 150+ characters with a space and `#`. Skill resolves the path via `runtime_capabilities.open_programs` (structured JSON) and reuses the id for every call. S, both. [8], [29], [59]
9. (12) Read actions of mutator tools take the global writer lock and the async path. `VariablesTool.isReadOnly()` is false for all actions (line 44); `executeGuarded` (`GhidrAssistMCPBackend.java:~1086-1094`) takes `McpMutationGuard.LOCK` for any non-read-only tool. Live: `variables action=list` task `55a01c0b...` stayed RUNNING at 0% for over 100 s while a concurrent `get_code` on the same function finished in seconds. Make `isReadOnly`/`isLongRunning` per action so `variables list`, `struct field_xrefs`, `comments get/list`, `types get/list` run synchronously without the lock. M, server. [31]
10. (12) `set_function_prototype` appends "Applied prototype: ..." to the function comment on every call (`SetFunctionPrototypeTool.java:226-239`), is annotated idempotent (lines 36-38) while the comment grows, accepts only `function_address` via `getFunctionAt` (lines 158-166), and duplicates `VariablesTool.executeSetPrototype` (lines 271-280). Remove or gate the auto-comment, accept a function name via `FunctionLookup`, return `function.getPrototypeString()` as stored. S, server. [32]
11. (12) Project-ops guidance must encode the tool-enforced state machine and the read-only trap. `ProjectRepositoryTool.java:98` refuses mutations while the DomainFile is changed (save first), `:116-119` refuses checkin when `canMerge`, `:131-134` merge returns `awaiting_user_resolution`; `SaveProgramTool.java:103-110` refuses during an active transaction. Live: 12 to 14 of 32 open programs have `version=-1, read_only=true, can_save=false`, including `inotify_service` and `speaker_service` which are also `dirty=true`, so annotations written there are lost. The porting skill needs a pre-flight check on target `read_only`/`can_save`. In headless mode `getAllOpenPrograms` is a singleton (`GhidrAssistMCPHeadlessServer.java:236-241`). M, both. [35], [59]
12. (12) Skills must branch on gui/headless and never trust the active program in a GUI session. Headless disables `open_program`, `close_program`, `project_files`, `project_repository`, `get_current_address`, `get_current_function` (`GhidrAssistMCPHeadlessServer.java:260-275`); in GUI mode the active program follows CodeBrowser focus (`GhidrAssistMCPManager.java:256-260`). Core rule: read `runtime_capabilities.gui` once, always pass `program_id`, treat the `[Context] Operating on:` preamble as a check. S, plugin. [61]
13. (11) Plugin manifest hygiene. Installed `plugin.json` has no `version`; the local marketplace advertises 34 tools at 1.0.0 against 145 live. Add `version` synced with `@extversion@`, `repository`, `homepage`, `keywords`, `mcpServers: "./.mcp.json"`. Keep plugin name and server key `ghidrassist` so the `mcp__plugin_ghidrassist_ghidrassist__` prefix used by permission rules and `allowed-tools` survives. Document `/plugin uninstall ghidrassist@custom-plugins` before adding the repo marketplace. Evidence: https://code.claude.com/docs/en/plugins-reference. S, plugin. [5]
14. (11) Use skill `allowed-tools` with the scoped prefix for the read-only pipeline tools (`get_code`, `function_byte_matcher`, `string_anchor_matcher`, `vt_matches`, `get_basic_blocks`, `wait_task`, `get_task_status`) and leave every mutator out so writes still prompt. Caveat from the judges: the grant lasts one turn, not a whole session. S, plugin. [6]
15. (11) Define the matcher result shape now. Per candidate: `target_address`, `target_function_entry`, `at_entry`, `target_name`, `target_name_source`, `source_size`, `target_size`, `size_delta`, `size_ratio`, `confidence`; top level: `candidate_count`, `pattern_hex`, `masked_byte_ratio`, `scan_truncated` (20-hit cap at `FunctionByteMatcherTool.java:135`). Today the confidence formula (lines 240-266) gives near 1.0 to every entry hit of similar size, so uniqueness is the real discriminator and is not a field. `string_anchor_matcher.isLongRunning()` is true (line 47), so its advertised schema is the `anyOf[completion, taskSubmission]` union (`McpOutputSchemas.java:44-53`) and the skill must handle a task id first; put only JSON primitives in the maps because `withJsonFallback` replaces the whole result on serialization failure (`McpResultContent.java:41-44`). S/M, both. [21], [12]
16. (11) `function_byte_matcher` is synchronous and scans all memory. It declares only `isReadOnly()` (lines 40-43), so the async path is never used; `Memory.findBytes` runs from min to max address including data and ELF pseudo-spaces (lines 131-153). Mark it long-running, restrict to executable blocks by default, accept `range_start`/`range_end`. The live timeouts are confounded by the selector hang (item 5), so scan length as the cause is unproven. S, server. [20]
17. (11) Shrink alias descriptions. `ToolAlias.java:21-22` returns "Compatibility alias for X. " plus the full target text, so 14 pairs (`GhidrAssistMCPBackend.java:322-335`) are indistinguishable in deferred search and the alias names (`list_functions`, `get_hexdump`, `get_function_info`) often match queries better. Return "Alias of X; call X instead." Update `CLAUDE.md` and the 0762 SKILL.md, which reference alias names. S, server. [16], [38]
18. (11) `search_bytes` fallback path has no machine-readable output: `SearchBytesTool.java:32-39` inputs are pattern/limit only, scan is full memory (lines 94-101), output is prose lines (114-123). Add `matches[{address, function_entry, at_entry, offset_in_function, block_name}]`, `count`, `truncated`, `range_start`/`range_end`, `executable_only`. S, server. [27]
19. (11) Stripped-target pre-pass. `BulkRegionTransfer.detectOffset` requires `getFunctionAt(matchAddr) != null` ("Target may be missing function definitions"), byte matcher gives no entry bonus without a function, string matcher counts only `getFunctionContaining` references. The skill must run `scan_function_candidates` plus `create_functions_at_addresses` and `fid_identify_functions` before matching, and must steer away from `program_diff` ("Does not align relocated programs"). S, plugin. [28]
20. (10) Prompts need tool-accurate write-back steps. `DocumentFunctionPrompt.java:117-142` ends at a Doxygen block with no `comments action=set`; `AnalyzeFunctionPrompt` asks for a suggested name but never says `rename_symbol`; `ReverseEngineerStructPrompt.java:31-56` hand-derives offsets and ignores `struct action=auto_create` (`StructTool.java:1099-1110`). Every prompt has its own `findFunction` matching `function.getName().equals(identifier)` while tools use `FunctionLookup.findByQualifiedName`, and prompts inline full decompilation with no `max_chars`. M, server. [34]
21. (10) `analyze_function` tool is misnamed: `GetFunctionInfoTool.java:67-75` returns a six-line header, its description says "detailed information", it collides with the `analyze_function` prompt and sits next to `analyze_program` (a long mutation) in search. Rewrite the description to state what comes back and route to `get_code`/`xrefs`/`get_call_graph`. S, server. [40], [36]
22. (10) Ship a `CLAUDE.md` template for RE projects that consume the plugin (program_id table, "save_program only when asked", "never construct program_ids"). The user's active RE project `CLAUDE.md` has zero Ghidra content. S, plugin. [60]
23. (9) Family cross-references in descriptions: `get_functions`/`search_functions_by_name`/`function_inventory`/`export_function_signatures`/`search_symbols_batch`, and `xrefs`/`xrefs_batch`/`get_call_graph`/`get_basic_blocks` never point at each other, and `XrefsTool.java:40` claims call-graph traversal. Add one "Prefer X when ..." clause per member. S, server. [41]
24. (9) Add a catalog lint JUnit test asserting the description template (verb first, first sentence <= 120 chars, alias stubs <= 80 chars naming the canonical, paged tools say "paged"). `src/test/java/ghidrassistmcp/` already exists. S, process. [46]

### Better ideas that change approach B

1. Put the core operating guide in the server `instructions` string, not a fourth skill. `GhidrAssistMCPServer.java:122,127` already pass `backend.getInstructions()` and Claude Code injects it at connect time with no invocation step; a loaded skill is a recurring per-turn token cost. Move the eight-paragraph Codex body (`.agents/skills/ghidrassist-mcp/SKILL.md:6-22`: truncation flags, per-row batch errors, `after_version`, `manager_instance_id`, preview-token regeneration) into `McpBackend.getInstructions()`, plus the three Claude-specific additions (tool prefix, 25k spill rule, gui/headless rule). Keep one source text (e.g. `docs/SKILL_CORE.md`) that generates both the instructions string and the Codex SKILL.md, with a build check that fails on divergence. This unparks the "shared skill core" (line 115) for free. [0], [63]
2. Replace the prose-first `list_binaries` with a compact structured result (`program_id`, name, path, version, dirty, read_only, can_save, language, format) with a declared schema, deduped by file_id+version, and rewrite its description and footer to say "copy program_id". `runtime_capabilities` already returns the same list as JSON. [13], [14]
3. Add a bulk exact first pass before any per-function matching: join `function_inventory` (entry_bytes plus hash, paged, schema-bearing, `FunctionInventoryTool.java:131`) and `export_function_signatures` (`ExportFunctionSignaturesTool.java:36-60`) on entry-byte hash. Consider a server tool `function_inventory_join(source, target, key=entry_hash|masked_hash)` returning unique/ambiguous/unmatched buckets so the skill never holds two inventories in context. The hash should be over operand-masked bytes, the same fix as Overlooked item 1. [24]
4. Split `bulk_region_transfer`: expose offset detection as a read-only `region_offset_probe(source, target, range)` returning offset, agreement count, samples[], warnings (today reachable only through the mutating tool with `dry_run` and prose parsing), and add `commit_policy: all_or_nothing|verified_only` because `transferLabels` commits only when failures and mismatches are both empty (line ~502). [25]
5. Use bookmarks (category `PORT`) or VT accept/reject status as the cross-session progress ledger instead of the old `docs/ghidra-port-progress.json` (0762 SKILL.md:163-165). `BulkTransferLabelsTool.java:70` already accepts a bookmarks array per row, so the ledger entry rides in the same transaction as the rename; `bookmarks(action=list, category=PORT)` yields the resume set. Codex gets the same view. No hooks needed. [26]
6. Collapse the mutate-then-verify round trip. Add optional `return_code` (bounded by `max_chars`) to `variables`, `set_local_variable_type`, `set_function_prototype`, `struct set_field/name_gap/auto_create` that re-decompiles once and returns the new C plus variables (`VariableRetypeSupport.java:75-78` returns no code today), and add a `code` field to structured `get_code` (`GetCodeTool.java:206` uses `getC()` only in the text path). The deep-function prompt becomes decompile once, mutate with `return_code`, no separate verify. [33]
7. Porting skill design: keep the 0762 pipeline's ordered gates, the 70-94% user-approval tier, the "Red Flags - STOP" table, the re-decompile verify step, and "Common Mistakes" (SKILL.md 24-46, 87-102, 167-175). Drop hard-coded program names, the `mcp__ghidra__` prefix, the tracker path, and the "never batch" rule. Move PowerPC VLE and r15/SDA rules (lines 71-76, 121-133) to `references/arch/powerpc-vle.md` loaded only when the language is PowerPC. Replace steps 3-5 with: exact hash join, then `string_anchor_matcher`, then `function_byte_matcher`, then VT correlators, then `bulk_transfer_labels dry_run=true`, user review, apply, `save_program`. [3], [55]
8. Set `_meta["anthropic/requiresUserInteraction"]: true` on `bsim_drop_database`, `project_files` delete, `write_bytes`, `patch_bytes`, `patch_instruction`, `close_program`. Server-side, non-autonomous, forces a prompt in every mode. [7]
9. Adopt one description template ("<Verb> <object>. Input: ... Output: JSON|text, paged|bounded|complete. Program: program_id. See also: ...") and apply it only to the ~15-25 workflow tools plus the aliases and contradictions (`get_binary_info` says "currently loaded program"; `function_byte_matcher` says "program names"), not the 145-tool catalog. The selector text lives only in the augmented schema (`GhidrAssistMCPBackend.java:~413`), which is hidden under deferral. [42], [17]

### Cuts and deferrals

1. Remove "declared output schemas" as a headline for the bulk transfer tools; they already emit `structuredContent`. Keep a one-line `getOutputSchema()` per tool because it gates `validateCompletion` and the async union advertisement, and shrink the prose block to a one-line summary so the JSON is the single payload. [11], [49]
2. Defer the 7-prompt rewrite out of phase 1. A plugin skill with positional arguments (`/ghidrassist:port-functions <source-path> <target-path>`) drives porting with no server change; the prompt interface rework (Corrections item 8) is medium effort for no phase-1 gain. When prompts are revisited: cut `trace_network_data` (516 lines of socket API tables, off-priority), rename prompts that collide with tool names (`analyze_function`, `compare_functions`), and make `compare_functions` the two-program prompt (`CompareFunctionsPrompt.java:31-53` resolves both functions in one program). [51], [36]
3. Collapse four skills to three: fold project operations into the core `references/` (content already exists in `docs/WORKFLOWS.md`), keep porting and deep-function separate because their trigger vocabularies and tool sets are disjoint and a merged SKILL.md would exceed the 500-line guideline. With Better idea 1 the core skill becomes a thin pointer to `references/`. [1], [0]
4. Delete `claude-code-integration/hooks/` (matcher `mcp__ghidra__rename_symbol` never fires; hooks are out by decision 3) and `claude-code-integration/scripts/` (superseded by `create_function`, `disassemble_at`, `create_memory_block`; the third is MPC5676R-specific). Decide explicitly whether `claude-code-integration/**` ships inside the extension zip: `build/install-stage-12.0.3/GhidrAssistMCP/claude-code-integration/` exists today; either add a `buildExtension.exclude` next to `build.gradle:88` `exclude 'lib/**'` or document the offline install path. [6], [9], [55]
5. Cut catalog-wide description tuning (line 93); scope it as in Better idea 9. Explicit tool names in the skills sidestep deferred search on the critical path. [17], [54]
6. Drop the six resource templates from the Claude plan or replace them with concrete per-open-program resources computed at `resources/list` time. Live project paths contain `#` and need `%23` encoding through `GhidrAssistMCPBackend.java:734`. [58]
7. Do not add tool icons or populate `title` (backend sets `title(tool.getName())`, identical to name); Claude Code renders neither. Keep prompt argument completion parked; when prompts take a program argument, timebox a one-hour spike (`SyncSpecification.completions(...)` exists in SDK 2.0.1). [18]
8. Defer the deep-function and project-ops skills and the shared-core generator until the porting skill has run once end to end. [55]

### Recommended build order

1. Reproduce and fix the selector hang (`ProgramIdentity.resolve`, `getSharedProjectURL(null)` at lines 19/37/57) and dedupe `getAllOpenPrograms` by file_id+version. Add the scripted live conformance run and record it. Nothing else is testable before this. [56], [47], [14]
2. Make `isReadOnly`/`isLongRunning` per action, add the inline grace wait in `executeToolAsync`, return the result from `wait_task` at terminal state. [30], [31]
3. Compact structured `list_binaries` with `program_id` guidance; expand `McpBackend.getInstructions()` from the Codex skill body plus prefix, spill rule, gui/headless rule; shrink alias descriptions. [13], [0], [16]
4. Matchers: instruction-model masking, `isLongRunning` and executable-only scan on `function_byte_matcher`, `structuredContent` plus `outputSchema` with the defined candidate fields on both matchers, structured `search_bytes`. [19], [20], [12], [21], [27]
5. `bulk_transfer_labels`: prototype validation in dry run, `name_policy`, current-name provenance in items, `outputSchema`, one-line prose. `vt_matches`: names, filters, sort. [22], [23], [11]
6. Plugin: `.claude-plugin/plugin.json` with version and `mcpServers`, `.claude-plugin/marketplace.json`, keep name and server key `ghidrassist`, one porting skill (`skills/port-functions/SKILL.md`) with project-path arguments, trigger-phrase description, `when_to_use`, `argument-hint`, `allowed-tools` for read-only tools, arch rules under `references/`, stripped-target pre-pass, PORT bookmark ledger, target `can_save` pre-flight; delete `hooks/` and `scripts/`; README install section and CLAUDE.md template. Run it once against the VCM2_SO to VCM3 pairs. [5], [2], [6], [3], [26], [28], [35], [60], [64]
7. `_meta` size budgets and default clamps on `get_code`, `get_data_at`, `get_basic_blocks`, `read_memory_table`, `function_inventory`, list tools; `requiresUserInteraction` on destructive tools. [10], [44], [7]
8. Deep function: `set_function_prototype` cleanup, `return_code` on mutators, `code` in structured `get_code`, prompt write-back steps and shared `FunctionLookup` if prompts are kept; then the deep-function skill. [32], [33], [34]
9. Project ops: state-machine guidance in core `references/`, per-program triage from `runtime_capabilities`, headless caveats. [35], [61], [1]
10. Optional: hash-join tool, `region_offset_probe` and `commit_policy`, description template for the workflow set, catalog lint test, refresh repo `CLAUDE.md`. [24], [25], [42], [46], [64]

### Rejected or low-confidence items

- [50] "Result-size work reduces to get_hexdump": rejected; `get_code` default `max_chars` 200,000 is roughly twice the client spill threshold and `get_basic_blocks` and the list tools are unbounded.
- [20] attribution of live `function_byte_matcher` timeouts to scan length: low confidence; every selector-bearing call times out today, so the design fix stands but the live evidence is confounded.
- [14] causation of the server-wide hang from two by-name calls: hedged by the reviewer; the exact-program_id reproduction shows the hang is not specific to name selectors.
- [49] "skip output schemas entirely": rejected as stated; schemas gate `validateCompletion` and the async union, so keep the one-line declaration.
- [53] and [39] and [57] and [52] and [37] and [38] and [29] and [59] and [48] and [45]: duplicates merged into the items above; no distinct content dropped.
- [43] BSim description indistinguishability (four query tools, templated job-control text in `BsimTool.java:19-22`): valid but off the critical path; fold into the description template pass if BSim enters the porting pipeline.
- [18] icons/title as dead weight: accepted as a cut above; the claim that Claude Code renders no titles is plausible but not evidenced.
- [41] cross-reference clauses labeled medium effort: kept, but the panel judges it small.
- [64] "README has no Claude mention": partly wrong; README line 3 links the Claude vs Grok compare, though no Claude Code install section exists.
- [46] catalog lint test premise "no test suite": stale; `src/test/java/ghidrassistmcp/` already has JUnit tests, which makes the item easier.
- [6] "allowed-tools is the only lever": overstated; permission allow rules also exist, and the grant lasts one turn.
- [24] `function_inventory_join` server tool: speculative until the hash-join has been tried from the skill with paged inventories.

### Post-panel verification (same day)

- Elicitation correction confirmed. The Claude Code MCP page has a section
  anchored `#respond-to-mcp-elicitation-requests` and documents both
  `_meta["anthropic/maxResultSizeChars"]` and
  `_meta["anthropic/requiresUserInteraction"]` as `tools/list` `_meta`
  entries. The constraint table rows for elicitation, annotations and result
  size above are superseded by Corrections 1 to 3.
- Selector hang (Overlooked item 5) did not reproduce after the panel
  finished. `get_binary_info` with `program_name=/NewFolder/VCM3/VCM#_SOLIB/led_service`
  and with the full `program_id` (space and `#` included) both returned in
  under a second. The panel ran seven agents concurrently, and item 9 shows a
  `variables action=list` task holding the global mutation lock for over
  100 seconds during that window. The likely cause is lock contention from
  non-read-only read actions, not selector resolution. Keep item 5's
  conformance script and the `getAllOpenPrograms` dedupe; treat the
  `getSharedProjectURL` hypothesis as unproven.
