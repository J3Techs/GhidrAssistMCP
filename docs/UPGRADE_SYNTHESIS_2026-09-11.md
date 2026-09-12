# GhidrAssistMCP upgrade audit and next steps

Audited September 11, 2026 (America/Phoenix), against HEAD `2381830` and the current working tree. This is a source audit and proposed implementation sequence, not a report of new product changes or live testing.

The consolidated [implementation plan](MCP_UPGRADE_IMPLEMENTATION_PLAN.md) defines the work packages, dependencies, contracts, acceptance tests and release gates. Use that plan for execution; retain this document as the supporting audit.

## Recommendation

Keep the shared Java server and build thin Claude and Grok integrations around it. Prioritize request dispatch, compact discovery, truthful annotation transfer, and architecture-aware matching before making cross-binary porting the flagship workflow. Ship small, independently verifiable changes rather than another catalog-wide modernization.

The original Claude approach B is still the right scope, **with the later panel corrections and post-panel retraction applied**. The existing client comparison predates those corrections and is not a reliable implementation specification. Grok's client configuration/docs can proceed independently; the full porting workflow depends on the server fixes below.

### Design refinements from the follow-up Claude findings

- **Put the concise operating guide in server initialization instructions.** `McpBackend.getInstructions()` already provides the delivery point. Expand it from one checked-in, client-neutral text resource covering identity, GUI/headless differences, bounded output, generic tasks versus BSim jobs, and persistence. Package that same text into the client guides rather than maintaining divergent copies. Keep client-specific discovery/spill syntax and long architecture references outside the connect-time instructions. Verify actual client exposure; initialization guidance is not a substitute for enforced server contracts. [Existing instructions](../src/main/java/ghidrassistmcp/McpBackend.java).
- **Use project paths as convenient skill inputs, then resolve to exact IDs once.** Accept source and target selectors; resolve each against the current inventory and reject ambiguity before work begins. Paths containing spaces must still work through tested quoting or explicit argument fields. Whitespace-free and unique paths describe the reviewed session, not every Ghidra project. Preserve the opaque returned ID for subsequent JSON tool calls. The reported slash-command parsing limitation does not prevent tool arguments from carrying IDs with spaces.
- **Use the `PORT` bookmark category for applied-transfer provenance.** Record source identity/address, operation identity and verification state at the destination function; apply the bookmark in the same transaction as the successful transfer. Save the program before claiming a durable checkpoint, and reconcile changed program revisions on resume. VT accept/reject status remains the authoritative match-review ledger when VT is used. Do not mark a transfer verified solely because its rename succeeded.
- **Make bounded `return_code` a concrete deep-function deliverable.** Add opt-in post-mutation code to retype/prototype operations, with exact program/function identity, resulting prototype and revision, truncation information, and separate mutation/verification outcomes. A decompile failure after commit must report “mutation applied, verification unavailable,” not imply rollback or invite automatic mutation retry. Use the shared decompiler service and detect intervening changes; avoid extending the global writer-lock hold just to format a result. Test successful code return, decompile failure after commit, and concurrent revision change.

The seven-prompt rewrite is deferred completely from this release. A porting skill supplies the workflow entry point. These refinements reduce duplicated guidance and round trips without requiring a new server orchestration layer.

## Evidence and baseline

Read the Claude integration ideas including its panel review and final addendum; Grok client review; client comparison; Grok fix preparation, repair/install report, and four repair track reports; root `CLAUDE.md`; and the modernization report. Checked the relevant dispatch, task, identity, discovery, result, matcher, transfer, VT, prompt, build, and test sources.

- HEAD is `2381830` (`Modernize MCP integration and fix tool correctness and lifecycle`). The old Grok preparation's pending defects were subsequently repaired; do not restart that backlog from `5b3a058`.
- The saved installation receipt records 245 tests: 243 passed, two external BSim tests skipped, zero failures/errors, plus a successful disposable headless smoke. These are **previous results**, not tests executed during this audit.
- Recomputed hashes for all **233 source/build entries present in the installation source manifest: zero mismatches**. This connects those recorded repairs to the inspected source despite the receipt identifying a dirty build on the older commit. It does not establish the identity of the currently loaded GUI extension or cover files absent from the manifest.
- Build dependencies remain MCP SDK 2.0.1, Jetty 12.1.13, Jackson 2.21.1. Recorded catalog: 145 registered names, 142 default enabled; the installed headless smoke recorded 139 enabled. Treat these as mode-specific figures, not conflicting counts.
- At audit start, `README.md` was modified and the three client review/comparison documents were untracked. This audit preserves them and adds only this synthesis.

Baseline evidence: [repair/install report](GROK_REPAIR_AND_INSTALL_2026-09-11.md), [installation receipt](../build/install-smoke-grok-fixes-20260911/install-receipt.json), [source manifest](../build/install-smoke-grok-fixes-20260911/source-files.json), [build](../build.gradle).

## Findings that change the plan

| Priority | Finding | Evidence and disposition |
| --- | --- | --- |
| P1 | Read actions on mixed tools enter the global writer lock. Several also always submit tasks. | `VariablesTool` and `StructTool` classify every action as mutating/long-running; `CommentsTool` and `TypesTool` classify all actions as mutating. Backend uses these tool-wide flags for actual dispatch. Fix execution classification, preserving conservative catalog annotations. [Backend](../src/main/java/ghidrassistmcp/GhidrAssistMCPBackend.java#L1086), [tool interface](../src/main/java/ghidrassistmcp/McpTool.java). |
| P1 | Bulk transfer has incomplete preview and success semantics. | Prototype parsing is inside `!dryRun && !sameName`; same-name prototype updates are skipped. Rename replaces existing name provenance with `IMPORTED`. `ApplyFunctionSignatureCmd.applyTo`'s boolean is ignored, exceptions can leave a row counted successful, and the final structured result omits the prose error list. These are source-confirmed paths, not newly executed reproductions. [Transfer](../src/main/java/ghidrassistmcp/tools/BulkTransferLabelsTool.java#L189). |
| P1 | Default masked matching is not architecture-neutral. | Byte matcher contains VLE-specific byte heuristics without checking language; region matching uses fixed two-of-four-byte masks. Neither establishes ARM/Thumb or x86 correctness. The score is a heuristic, not a calibrated probability. [Byte matcher](../src/main/java/ghidrassistmcp/tools/FunctionByteMatcherTool.java#L194), [region matcher](../src/main/java/ghidrassistmcp/tools/BulkRegionTransferTool.java#L252). |
| P1 | Discovery is unnecessarily large and gives conflicting targeting advice. | Capabilities always includes all program descriptions; `list_binaries` is unpaged prose and directs clients to `program_name` despite exact-ID guidance elsewhere. Grok's reported truncation is historical live evidence, not remeasured here. [Capabilities](../src/main/java/ghidrassistmcp/resources/RuntimeCapabilitiesResource.java#L65), [listing](../src/main/java/ghidrassistmcp/tools/ListProgramsTool.java#L34). |
| P2 | Async completion costs extra calls; queue/result admission remains unbounded. | Uncached `get_code` always submits when async is enabled. `wait_task` deliberately returns metadata only. Generic manager uses a fixed executor with an unbounded queue and retains results outside the response cache's byte budget. Improve admission and measure timing before adding blanket grace waits. [Dispatch](../src/main/java/ghidrassistmcp/GhidrAssistMCPBackend.java#L519), [wait](../src/main/java/ghidrassistmcp/tools/WaitTaskTool.java#L21), [manager](../src/main/java/ghidrassistmcp/tasks/McpTaskManager.java#L80). |
| P2 | Structured results and declared schemas are different work. | Bulk transfers already return structured content but lack output schemas; matchers need real result models. Schema validation occurs only for tools declaring a completion schema. Preserve one complete JSON text fallback for clients that need it. [Validator](../src/main/java/ghidrassistmcp/McpOutputSchemas.java#L56), [fallback](../src/main/java/ghidrassistmcp/McpResultContent.java). |
| P2 | Bounds are uneven, not universally absent. | `get_code`, legacy function listing, xrefs and call graphs already received bounds. Basic blocks still lacks bounds; legacy data/import/segment listing paths still use weak numeric parsing. The imports reference mode has its own bounds and should retain them. Prioritize actual gaps and aggregate UTF-8 size. [Basic blocks](../src/main/java/ghidrassistmcp/tools/GetBasicBlocksTool.java#L68), [imports](../src/main/java/ghidrassistmcp/tools/ListImportsTool.java#L62). |
| P2 | VT is useful now but expensive to review through the client. | `vt_matches` pages matches but lacks name/provenance fields, filtering and stable score ordering. Extend the existing tool before inventing a new matching orchestration tool. [VT listing](../src/main/java/ghidrassistmcp/vt/VTTool.java#L145), [match row](../src/main/java/ghidrassistmcp/vt/VTSupport.java#L111). |

### Corrections and recommendations not to adopt blindly

1. **Selector hangs are not an established identity bug.** The Claude document's final addendum says the hang did not recur and both exact ID and path returned quickly. Writer-lock contention is plausible, but the source alone does not prove it caused those timeouts. Add phase timings and a bounded concurrency fixture; do not rewrite URL resolution based on the abandoned `getSharedProjectURL` hypothesis.
2. **Do not blindly deduplicate by file ID/version.** The manager already deduplicates repeated references to the same Program object. Distinct Program instances may have different unsaved states even if their domain identities coincide. Decide whether to reject collisions or expose a session instance selector; never silently choose one mutable instance. Include project origin in any persistent identity key. [Identity resolver](../src/main/java/ghidrassistmcp/ProgramIdentity.java#L42), [manager listing](../src/main/java/ghidrassistmcp/GhidrAssistMCPManager.java#L236).
3. **Do not translate per-action execution flags into optimistic tool annotations.** A mixed tool remains mutating in `tools/list`; only a validated read action can bypass the writer guard. Unknown actions must not get that bypass. Aliases must delegate the same classification. Static async schema advertisement must still accept every possible submission/completion shape.
4. **`preview_annotations=true` is not a whole-operation dry run.** It leaves name/prototype writes possible when `dry_run=false`. Document this immediately, then make preview/apply semantics consistent without silently changing existing clients' requests.
5. **Raising a client result threshold does not bound server output.** Claude's `anthropic/maxResultSizeChars` is tool `_meta` and raises its persistence threshold; it is not a server cap. Paging and serialization budgets come first. Claude supports elicitation, so the original unsupported claim is stale. Neither feature requires adoption in this upgrade. [Current Claude MCP reference](https://code.claude.com/docs/en/mcp).
6. **Claude support is version/runtime dependent.** Current documentation describes progress-aware idle handling and newer MCP runtimes; the old blanket “progress unsupported” row is too broad. Verify actual installed versions for structured results, resource-template discovery and prompt quoting instead of carrying client limitations forward as universal facts. [Current Claude MCP reference](https://code.claude.com/docs/en/mcp).
7. **Keep complete JSON for text consumers.** Structured content plus its JSON fallback necessarily repeats data on the wire. Remove duplicate prose/detail within text content, but do not replace JSON with a digest. Measure what each client actually counts.
8. **Do not turn stripped-binary preparation into an automatic mutation pre-pass.** Missing function definitions should produce explicit prerequisites/candidates. Function creation and persistent annotation transfer need a separately understood plan; not every low-confidence candidate merits a new function.

## Proposed implementation sequence

### 1. Establish trustworthy dispatch and evidence

Add argument-aware execution traits for the known read actions in variables, structures, comments and types. Keep tool-wide annotations conservative. Separate selector time, queue wait, guard wait, execution, serialization and response bytes in bounded diagnostics. Refresh stale `CLAUDE.md` in the same change so subsequent work uses the actual architecture and build commands.

Acceptance: deterministic latch-based tests show a read action does not wait for the unrelated writer guard, mutation actions still serialize, invalid actions do not bypass it, aliases behave identically, and cancellation/shutdown retain the ownership guarantees already repaired. Include both async-enabled and disabled dispatch. No claim of snapshot-consistent reads during arbitrary GUI analysis.

Add a small conformance harness covering initialization, capabilities, program enumeration, exact ID/path/ambiguous name selection, a resource read and paged query. Capture loaded-build identity and per-phase timing. Run first against disposable GUI/headless fixtures; ordinary read-only checks in the working GUI can then establish whether reported latency persists.

**First implementation slice:** execution traits + alias propagation + focused regression tests + `CLAUDE.md` refresh. Keep inline grace waits and global identity deduplication out of that patch.

### 2. Make discovery and completion economical

Add an explicit compact capabilities mode and structured, paged `list_binaries` with exact selectors, language and persistence state. Preserve the current capabilities default initially because existing clients read `open_programs`; client guides can request compact mode. Any later default change needs a versioned contract and migration note. Keep tool/resource behavior aligned.

Add an opt-in bounded terminal-result field to `wait_task` while preserving its metadata-only default and `get_task_status`. Bound generic queue admission and retained result bytes with explicit busy/expired/result-too-large outcomes; rejected submissions must release their consumers. Consider a small configurable inline completion wait only after latency measurements justify it.

Fix actual legacy bounds gaps, retaining explicit truncation and continuation. Target compact discovery plus a normal program-list page below **20,000 UTF-8 bytes** in a 32-program fixture, including long/non-ASCII paths and full result serialization. Oversized individual fields/rows must have an explicit retrieval path rather than silently truncated IDs. This is a proposed acceptance budget, not a current measurement.

### 3. Make transfer previews and results authoritative

Validate prototypes using isolated type staging during dry runs; apply prototypes independently of whether the name changes. Add an explicit name policy that preserves user names by default, with a documented compatibility change for replacement. Check native command outcomes and report name/prototype/annotation results separately, including errors in structured output.

Use the existing BSim implementation as the reference for preserving non-default name/signature sources and binding previews to fingerprints. Reuse its proven policy concepts without assuming its native signature-copy path validates incoming C prototype text; bulk transfer still needs isolated parsing and command-outcome checks. [BSim application policy](../src/main/java/ghidrassistmcp/bsim/BsimMatchOperations.java#L284).

Define one transaction policy for the whole requested transfer, with rollback reflected accurately in row and aggregate counts. Check target writability and save capability before a persistence-oriented workflow. Bind reviewed plans to target identity/revision so stale previews cannot silently apply to changed state. Add output schemas to both bulk transfer tools.

Acceptance: same-name prototype update, invalid prototype preview without type-manager side effects, preserved user-defined name, explicit replacement, command-false handling, mixed-row rollback, stale preview rejection and save/reopen verification on disposable programs.

### 4. Validate matching before advertising generic porting

First gate unsupported masked modes explicitly; preserve a clearly named exact-byte option. Implement instruction/operand-aware matching only where validated, with language/compiler/context compatibility checks. Operand masks need careful selection: masking every operand can erase useful evidence. Handle mixed instruction widths, undefined bytes, noncontiguous bodies and low-information patterns explicitly.

Give both matchers structured candidates and output schemas: program identity/revision, entry/interior location, current name/source, sizes, scoring evidence, candidate count and scan completeness. Bound search scope and wire in cancellation. A hit cap must not imply uniqueness; return ambiguity/incomplete-scan status. Do not reuse the old heuristic percentage as a probability of correctness.

Improve `vt_matches` with source/destination names, provenance, filters and deterministic ordering/paging. Prefer native VT correlators where suitable while validating custom matchers; native availability does not itself prove a match, and BSim is another existing native matching family. Avoid claiming VT is the only architecture-capable option. Use accepted/rejected VT state for review and `PORT` bookmarks for applied-transfer provenance as specified above.

Acceptance: disposable PowerPC VLE, ARM/Thumb and x86 fixtures with positive matches and misleading near-matches; entry/interior distinctions; capped scans; cancellation; duplicate correlator results; and stable pages or explicit revision invalidation.

### 5. Package the client workflows

| Client | First deliverable | Validation |
| --- | --- | --- |
| Claude | Repository marketplace at `.claude-plugin/marketplace.json`; versioned plugin under `claude-code-integration/`; preserve plugin/server key `ghidrassist`; one porting skill with source/target path inputs and architecture references. Core rules come from initialization instructions. | Validate manifest and source paths; verify actual tool prefix, instruction visibility, quoted path arguments, skill invocation, exact selectors, task recovery, preview/apply/save on disposable pairs. Follow the supported [marketplace layout](https://code.claude.com/docs/en/plugin-marketplaces) and [skill frontmatter](https://code.claude.com/docs/en/skills). |
| Grok | `grok-integration/config.example.toml`, `docs/GROK_INTEGRATION.md`, and client-specific guidance for search/use, spill recovery, generic tasks versus durable BSim jobs, VT and persistence. | Verify supported config keys and skill discovery against the installed Grok build. The review's proposed 131072-byte cap is a starting point. Do not copy its timeout reductions without measurement or import the Codex allowlist. |
| Shared | One checked-in operating-guide resource used by server instructions and packaged into client guides, with thin client-specific wrappers. | Check generated/copied text for drift; validate public tool names/arguments against the generated catalog; test one complete match/review/apply/save/reopen workflow. Keep client names and discovery syntax in wrappers. |

Grok config/docs and Claude manifest scaffolding can be prepared before steps 3–4, but should not claim the unfinished porting contracts. Decide explicitly which client assets belong in the extension ZIP. Retire old hooks and architecture-specific scripts only after documenting replacements. Preserve existing resource templates for other consumers even if a Claude picker cannot show them.

Avoid new forced-approval hooks or metadata as the default upgrade path. The existing preview, conflict and persistence contracts are the immediate engineering work; client permission policy is a separate product choice. Do not copy the panel's fixed confidence-based approval tiers without validated scoring.

## Later work and release gates

Defer the seven-prompt rewrite: `McpPrompt.generatePrompt` accepts one Program and the server binds the current one, so cross-program prompts require interface/ownership work, not just Markdown edits. Start with the porting skill. The next deep-function increment combines prototype-comment idempotence, the bounded `return_code` contract above, and its skill; it does not depend on MCP prompt redesign.

Also defer a general skill-generation framework, a new inventory-join/offset-probe tool, schemas for all 145 names, per-client catalog filtering, durable generic job storage, and a new protocol adapter. Reusing the single operating-guide resource needs only a small packaging step and drift check, not that framework. Bounded task admission belongs earlier; full restart recovery is a separate design. Keep the server's currently advertised protocol and task limits truthful.

Each behavior change needs focused regressions. Run the coordinated suite and extension build at integration, then inspect dependency packaging and catalog/schema compatibility. Finish with disposable GUI/headless and actual Claude/Grok client smoke checks, recording build/client versions and result bytes. An installed archive and a running JVM are separate release facts.

Audit limits: no new Java tests, live MCP calls, GUI mutations, installation, global client configuration changes or external database operations were performed. Current Claude documentation was checked; Grok-specific capabilities and defaults remain evidence from the supplied review until version-specific client verification.
