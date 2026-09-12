# MCP upgrade implementation plan

Status: server implementation is integrated, with 369 tests (367 passed, two external-service skips), a validated extension archive and fresh packaged-JAR conformance/PORT workflows. See [final validation](UPGRADE_FINAL_VALIDATION_2026-09-12.md) and the [release-gate matrix](RELEASE_GATE_AUDIT.md). Client-specific and user-GUI installation acceptance remain explicit gates; source completion does not imply those environments were replaced.

Prepared September 11, 2026 (America/Phoenix). Baseline: repository HEAD `2381830`. This plan consolidates the [upgrade audit](UPGRADE_SYNTHESIS_2026-09-11.md), [Claude findings and corrections](CLAUDE_INTEGRATION_IDEAS_2026-09-11.md), [Grok client review](GROK_CLIENT_REVIEW_2026-09-11.md), and the subsequent design discussion. It supersedes their proposed work ordering, while preserving their historical evidence.

## 1. Outcome and scope

Deliver a shared Ghidra MCP server that selects programs reliably, keeps ordinary reads responsive, returns bounded and interpretable results, and transfers annotations with accurate previews and outcomes. Provide Claude and Grok with client-specific entry points into the same contracts. Complete a porting workflow and a deep-function workflow on disposable programs, including save/reopen verification.

The upgrade has three release milestones:

| Milestone | Required work | User-visible outcome |
| --- | --- | --- |
| M1: reliable interaction | WP01–WP06 | Correct read dispatch, compact discovery, shared operating instructions, fewer completion calls, bounded task/output handling. |
| M2: portable annotation workflow | WP07–WP10, porting portion of WP12 | Trustworthy transfer preview/apply, architecture-qualified matching, useful VT review, PORT provenance and working Claude/Grok porting packages. |
| M3: deep-function workflow and release | WP11, remaining WP12, WP13 | Retype/prototype with bounded returned code, completed client validation, packaged release and verified loaded runtime. |

All three milestones are included in this plan. They can be reviewed and released separately; M1 must not imply that generic masked porting is already supported.

### Decisions carried forward

1. One Java server and one client-neutral operating-guide source. Thin client wrappers contain naming, discovery, configuration and spill-recovery details.
2. Server initialization instructions deliver the concise core guide. A small packaging step reuses it in client references; no general skill-generation framework.
3. Preserve canonical tool names and compatibility aliases. Keep resources and existing prompts available; defer all seven prompt rewrites.
4. Skills accept source/target project selectors and resolve them once to opaque exact IDs. Never depend on GUI focus for a multi-call workflow.
5. Validate and preserve user annotations by default. Model mutation success, verification success and durable save as separate facts.
6. Use native VT where appropriate while custom masks are being qualified. BSim remains a separate available matching family and job system.
7. PORT bookmarks record applied-transfer provenance. Native VT status records VT match review. Neither eliminates explicit program/session saves.
8. Add opt-in bounded `return_code` to retype/prototype operations. A post-commit decompile failure cannot retroactively turn an applied mutation into a rollback.
9. No new hooks, unattended mode, forced-approval policy, per-client server catalog filtering, or client runtime embedded in the JVM.
10. Do not change protocol revision claims or convert custom tasks into MCP Tasks as part of this release.

## 2. Baseline, constraints and evidence rules

The [repair/install report](GROK_REPAIR_AND_INSTALL_2026-09-11.md) records 243 passing tests and two external BSim skips across 245 tests. The preceding audit compared 233 source/build entries against the saved installation source manifest and found zero differences. Those are historical results, not a new execution claim.

Recorded dependencies are SDK 2.0.1, Jetty 12.1.13 and Jackson 2.21.1; builds require JDK 25. The previous installed smoke used Ghidra 12.0.3 with Java 21. Recheck the chosen build/runtime pair during WP01 rather than copying an obsolete command from `CLAUDE.md`.

Preserve the user's existing README edits and untracked review documents. Work from the current tree, not the older Grok review commit. At implementation start, inspect applicable repository instructions and record any intervening source changes.

The historical selector hang did not reproduce after the Claude panel. Its cause is unresolved. Do not label URL lookup as broken without new evidence. Likewise, the earlier ARM/x86 inventory and Grok output cap describe that reviewed session, not a fresh observation.

Record evidence under a new `build/upgrade-validation/<run-id>/` directory and summarize it in a tracked validation report. Store build/client versions, test totals, selected configuration, request/result sizes, timing summaries and artifact hashes. Keep full local project identifiers out of generalized public reports where unnecessary.

## 3. Dependency and change sequence

| Work package | Depends on | Primary files/areas | Size |
| --- | --- | --- | --- |
| WP01 Baseline and conformance harness | — | validation tooling, `CLAUDE.md`, build documentation | S |
| WP02 Action-aware dispatch and timing | WP01 | `McpTool`, `ToolAlias`, backend, mixed-action tools | M |
| WP03 Program discovery and identity diagnostics | WP01 | `ProgramIdentity`, `ProgramSelection`, program listing, capabilities | M |
| WP04 Shared operating instructions | WP03 contract | `McpBackend`, packaged guide resource, client references | S |
| WP05 Task completion and admission | WP02 | task manager, wait/status schemas, backend | L |
| WP06 Bounded output and targeted descriptors | WP03, WP05 result contract | query tools, result/schema helpers, catalog tests | M |
| WP07 Transfer integrity and preview | WP03 | bulk transfer tools, annotation support, BSim policy reference | L |
| WP08 Matcher qualification and contracts | WP02, WP03, WP06 | byte/string/region matchers, bounded byte search | L |
| WP09 VT review improvements | WP03, WP06 | VT tools/support/options tests | M |
| WP10 PORT ledger and porting workflow | WP07, WP08, WP09 | bookmarks, workflow specification, fixtures | M |
| WP11 Post-mutation code and deep-function workflow | WP02, WP05, WP06 | retype/prototype tools, decompiler service, code result model | L |
| WP12 Claude/Grok packaging | WP04; workflow validation after WP10/WP11 | integration directories, manifests, skills, docs | M |
| WP13 Integration and release verification | all required packages | suite, archive, installed/runtime smoke, release evidence | M |

Sizes describe relative implementation/review scope, not promised calendar durations. WP03, client scaffolding and independent tool work can progress without waiting for unrelated changes. Backend, task schema and shared result changes must integrate in dependency order. This plan does not require parallel agents.

Before WP08 is complete, add an early, small guard against unsupported masked modes as part of that package's first change. Do not leave new client workflows recommending known-incompatible matching during the rest of implementation.

## 4. Work packages

### WP01 — Establish the baseline and a repeatable conformance harness

Deliverables:

- Record HEAD, working-tree changes, build toolchain, installed archive/JAR identity, and the identity advertised by a running test server. Distinguish source, archive, installed files and loaded JVM.
- Refresh `CLAUDE.md`: actual architecture, endpoints, dependencies, tests and supported build commands. Link to current documents instead of duplicating volatile tool counts.
- Add a reusable harness based on existing HTTP tests and disposable project fixtures. Cover initialize, tools/list, capabilities, listing, exact-ID/path selection, ambiguous/missing selection, resource read, bounded search and task completion.
- Create a validation evidence template with explicit source-only, fixture-executed, client-executed and installed-runtime labels.

Acceptance: the harness can run against an isolated endpoint, produces machine-readable pass/fail results, stops its owned process cleanly, and never needs to mutate a working user project. Record the baseline suite once; later run focused tests until the integration gate.

### WP02 — Separate execution traits from catalog annotations

Introduce an argument-aware execution-traits hook with conservative defaults. It determines writer-guard requirement and whether an invocation may use asynchronous execution. Keep the existing no-argument annotations for tools/list and the static “may submit a task” property for output-schema advertisement. `ToolAlias` delegates every execution trait.

Initial read-action allowlist:

| Tool | Read action | Execution rule |
| --- | --- | --- |
| `variables` | `list` | No writer guard; native decompilation may still take time. |
| `struct` | `field_xrefs` | No writer guard; bounded/cancellable traversal. |
| `comments` | `get`, `list` | No writer guard. |
| `types` | `get`, `list` | No writer guard. |
| `get_code` | all existing read formats | Preserve read-only behavior; fast completion addressed in WP05. |

All other actions retain their current conservative mutation classification until individually reviewed. Invalid actions fail validation; they do not receive a read bypass. BSim worker guards and cancellation's existing guard exemption must remain intact. Do not cache previously uncached read actions merely because they are now classified correctly.

Add bounded per-request timing for selection, queue, writer guard, execution and serialization, plus encoded result bytes. Use generated correlation IDs; avoid logging full tool arguments or decompiled bodies. Timing collection must not perform blocking network work.

Acceptance: deterministic latch tests prove read bypass, writer serialization, alias equivalence, invalid-action handling, and ownership through cancellation/shutdown. Test async on/off. Read bypass does not promise snapshot isolation from Ghidra GUI analysis.

### WP03 — Compact discovery and explicit identity collisions

Add structured, paged `list_binaries` while retaining its public name. Rows contain exact `program_id`, name, project origin/path, file/version identity, language/compiler information, active state, modification number, dirty/changeable/read-only/can-save state and collision diagnostics. Optional fields are explicitly nullable or omitted according to schema.

Use deterministic ordering and an inventory revision cursor. If open-program membership changes between pages, return an explicit restart condition instead of silently shifting offsets. Never truncate an identifier. The default page should be small enough for the 20,000-byte acceptance budget in WP06; callers can request smaller pages.

Repeated references to the same Program object may collapse. Distinct mutable instances with a colliding persistent ID remain visible and produce a selection error; do not silently deduplicate or choose one. This release does not invent persistent IDs for unsaved instances or guarantee that a project path is globally unique. Preserve existing unsaved-ID behavior and document its process scope.

Add `include_programs=false` to the capabilities tool as the compact path; preserve today's full default for compatibility. Compact output retains counts, active program, collision summary, build/protocol/mode and task limits. Reuse a shared snapshot implementation for the existing resource, which can retain its full representation. Core instructions and new client guides request compact mode explicitly.

Acceptance: duplicate names, same persistent ID on distinct instances, multiple origins, historical versions, spaces/`#`/Unicode, unsaved programs, closure during selection and inventory changes between pages. Ambiguous selection changes no database. Context in returned results identifies the selected program, not whichever window later gains focus.

### WP04 — Publish one concise operating guide

Create `src/main/resources/ghidrassistmcp/operating-guide.md` as the canonical core text. `McpBackend.getInstructions()` loads it with a tested fallback if packaging is faulty. Keep it concise: target at most 8 KiB UTF-8, with no client-specific prefixes or architecture tutorials.

Content: compact capabilities and paged program discovery; exact selectors; GUI/headless differences; result completeness; generic task lifecycle versus durable BSim jobs; cancellation semantics; dry-run versus annotation preview; target writability; separate program/VT/session saves; PORT resume rules; and when to consult detailed references.

Add a small deterministic packaging/check task that copies this text into client reference material. Preserve the existing Codex skill's client-specific wrapper and frontmatter. Verify generated/copied content is current; do not generate entire skills or place a long catalog in initialization instructions.

Acceptance: the packaged resource is present, initialize advertises the same text, documented names resolve in the catalog, wrappers do not contradict it, and actual Claude/Grok exposure is recorded in WP12. A client that does not surface instructions still has the packaged reference.

### WP05 — Reduce completion calls and bound generic work

Make three separately reviewable changes:

1. Add `wait_task(include_result=true, max_result_bytes=...)`. Keep metadata-only default. Return terminal outcome and an optional bounded nested operation result with separate error state. Preserve `get_task_status` for retrieval and older callers. Oversized results return explicit retrieval/size metadata, never partial JSON masquerading as a complete result.
2. Replace unbounded generic queue admission with configurable limits and a retryable `SERVER_BUSY` result before submission ownership escapes. Bound completed-result retention separately from the existing query cache. Define explicit `RESULT_EXPIRED` and `RESULT_TOO_LARGE` retrieval outcomes while retaining operation status; an applied mutation must not appear unexecuted because its payload was too large.
3. Add a short, configurable inline completion window for read operations that already use tasks. Submit once, wait briefly, return a validated completion if ready, otherwise return the same task ID. Do not execute twice, cancel on grace expiry, or release task-owned consumers prematurely. Cache hits continue to return immediately.

Starting limits to validate, not claims about the current implementation: four workers, 64 queued tasks, 1,024 retained terminal metadata records, 64 MiB total retained result data, 4 MiB per retained payload, one-hour maximum retention. Use exact serialized byte accounting for retained payloads and release the corresponding object graphs; document that this is not an exact heap ceiling. Evict payloads only after terminal state, retaining bounded outcome metadata. Running tasks are never evicted to satisfy a history limit.

Start the inline window at 500 ms, configurable from 0–1,000 ms. Measure tiny/cold/warm decompilation and contended workloads before choosing the shipped default. Apply inline waiting to reads first; do not globally delay every mutating submission. Update completion/submission unions, task errors, aliases and documentation together.

Acceptance: fast completion uses one tool call; slow completion can use submission plus one result-bearing wait; timeout leaves work running; progress-only wake does not claim a result; error payloads remain intact; queue saturation/rejection leaks no consumers; cancellation frees queued reservations exactly once; retention eviction never changes operation outcome. Preserve existing shutdown and script-runner lifetime tests.

### WP06 — Bound outputs and improve workflow descriptors

Fix the verified gaps: `get_basic_blocks`, `get_data_at`, legacy `get_data_vars`/`get_imports`/`get_segments`, plus aggregate budgets for large batch/inventory responses. Preserve bounds already present in code, xrefs, call graphs and structured imports. Reuse checked numeric parsing and common budget helpers.

Specify row and UTF-8 byte bounds separately. Account for context decoration, JSON escaping and the wire duplication caused by structuredContent plus a JSON text fallback. Emit exactly one complete JSON text fallback; short summary text may remain. Never implement truncation by cutting a JSON string. Rows/edges omitted for a budget carry explicit completeness/continuation metadata; large single fields have a narrower retrieval path or an explicit size error.

Acceptance budgets: each compact discovery response and default program-list page below 20,000 encoded bytes in the 32-program long-path fixture. Test boundary values, fractional/overflowing numeric input, non-ASCII strings, a single oversized row, and graph edge growth independently of node count. Other tools publish their own validated budgets; do not pretend a row cap bounds native decompiler allocation or regex CPU time.

Tune descriptions only for the workflow set: discovery, code, batch queries, task controls, matchers, transfer, VT review and saves. Lead with purpose and exact selector requirements. Shorten aliases to point to canonical names without removing them.

Add a `getToolMeta()` extension point only if the Claude size-threshold adjustment proves useful in the client smoke. Any `anthropic/maxResultSizeChars` belongs in `_meta`, does not enforce server bounds, and must not become a dependency for Grok. Forced-interaction metadata is outside this plan.

### WP07 — Make transfer validation and mutation truthful

Implement a shared transfer-plan representation reused by preview and apply. Retain `dry_run` and document that `preview_annotations` controls only optional annotations in the legacy interface. New client workflows use a whole-operation dry run, then apply the reviewed plan.

Plan rows include destination function/entry, requested and current name/signature, their source provenance, prototype parse outcome, annotation conflicts, intended changes and per-field outcomes. Resolve all targets and validate C prototypes in isolated staging before starting mutation. Prototype application must be independent of a rename. Check the native command return value and error status.

Add explicit name/signature preservation policies with conservative defaults, modeled on BSim: update default-origin values; preserve existing analyst values unless replacement is explicitly requested. Publish the compatibility change. BSim's native signature-copy policy is a reference, not a C-parser implementation.

Bind preview tokens to normalized operations, target instance/persistent identity, program modification number and applicable policy; include source identity/revision when the tool reads a source program. Supplying a stale token fails before mutation. Preserve direct calls by fully validating them immediately before apply; a token is not a new universal permission step. Client workflows always reuse their reviewed token. Bound token storage or use a deterministic fingerprint; do not add an unbounded preview registry.

Use whole-call rollback on mutating failure. Do not use nested Ghidra transactions as row savepoints; reject an incompatible enclosing transaction. Report committed, preserved, skipped, failed and rolled-back counts separately. Put every error in structured output and set tool error state consistently. Validate successful output shape before commit wherever possible; serialization failure after a commit must never imply no mutation occurred.

Add declared schemas to `bulk_transfer_labels` and `bulk_region_transfer`, keeping existing useful fields. Target write eligibility is enforced in tools; a workflow claiming persistence additionally requires `can_save` or an explicitly chosen supported persistence path.

Acceptance: same-name prototype change, prototype parse failure with no target type changes, user name/signature preservation, explicit replacement, native command-false, annotation conflict, stale preview, mixed-row rollback, cancellation and save/reopen. Verify source programs remain unchanged.

### WP08 — Qualify matchers for each architecture

First add language/context checks to both byte and region masking paths. Unsupported modes return an actionable error; do not silently apply VLE masks to ARM/x86 or silently switch a requested masked comparison to exact bytes. Preserve existing `mask_mode=none` as the explicit raw-byte comparison. Unknown modes fail validation.

Then implement a shared instruction-aware mask builder, selecting only the operand bits justified as relocatable by decoded instructions/operands. Preserve discriminating opcodes/registers where possible. Check source/target language, endianness, compiler/context compatibility, mixed-width instructions, undefined bytes, noncontiguous bodies and pattern specificity. Mark an architecture/mode supported only after its positive and negative fixtures pass.

Bound executable-memory scans by default, allow explicit ranges, and propagate the actual task monitor. Use asynchronous capability for expensive scans. Respect address-space boundaries and do not search unrelated pseudo-spaces by default. Fix the region verification path as well as initial offset discovery.

Define structured byte/string candidate contracts: source/target IDs and revisions, candidate address, containing function and entry flag, target name/provenance, sizes/ratios, pattern/mask evidence, score explanation, candidate count, scan completeness and continuation/scope. A 20-hit cap cannot establish uniqueness. A confidence score is ranking evidence, not an approval probability. Use proper JSON serialization for string anchors and expose full/truncated anchor state.

Add bounded structured `search_bytes` results for the fallback workflow, including entry/interior position and block. Do not replace all matching with a new join tool. A future exact-hash pass can use existing inventories after the quality of its fingerprints is measured.

Acceptance: PowerPC VLE, ARM/Thumb and x86 fixtures; genuine correspondences and lookalikes; unchanged versus relocated operands; low-information masks; interior hits; missing function definitions; capped/incomplete scans; cancellation and region mismatches. The supported-mode table in documentation is generated or checked against these fixtures.

### WP09 — Make native VT review practical

Extend `vt_matches` with source/destination names and provenance, match-set identity, status and score fields. Add match-set/status/minimum-score filters and stable ordering with a deterministic tie-breaker. Distinguish native scores from custom matcher scores.

Use bounded pages tied to a session revision; changes to correlator output or review state invalidate continuation explicitly. Filtering and sorting must not imply an unbounded retained match list; document scan cost if all matches must be visited. Add a declared output schema and preserve existing addresses/status fields.

Keep duplicate correlator associations visible with their match-set identity. A high score is not automatic acceptance. Retain existing accepted-match and fresh-preview requirements for markup, and keep VT session save separate from program save.

Acceptance: names and missing-name cases, filtering, stable equal-score ordering, duplicate sets, session revision changes, accepted/rejected state, and native apply/unapply surviving save/reopen. Reuse existing VT integration fixtures.

### WP10 — Build the PORT ledger and the porting workflow

Use NOTE bookmarks in category `PORT` at the destination entry, with compact versioned metadata: operation ID, source persistent identity/address, source fingerprint, destination fingerprint, matching method/evidence reference and verification state. Persistent fingerprints must be distinct from process-local modification numbers. Encode bounded metadata and define how repeated transfers update history; do not append unbounded text to one bookmark.

The initial bookmark records `applied_unverified` in the transfer transaction. If verification follows after commit, update it to `verified` in a separate explicit transaction only when identity/revision checks succeed. Saving commits the checkpoint to disk. Failed verification leaves honest provenance rather than a false completion marker. On resume, reconstruct the ledger from the program and recheck fingerprints; do not reuse an old process-local task ID or modification counter.

Porting skill workflow:

1. Read compact capabilities and enumerate programs; resolve source/target path inputs to exact IDs. Check mode, architecture, writable target and persistence path.
2. Inspect existing PORT/VT state and determine the remaining scope. Report missing function definitions as prerequisites; do not create them automatically from weak matches.
3. Obtain candidates using supported native VT, validated byte/string matching or available BSim. Prefer bulk/bounded queries and corroborate ambiguity with independent evidence.
4. Review selected associations; create a full transfer preview, inspect conflicts/provenance and preserve analyst work by default.
5. Apply the selected plan with its fresh token and PORT metadata; verify actual names/signatures and bounded code where appropriate.
6. Save the destination and any changed VT session independently; inspect each save result. Resume from persisted state, not a client-only JSON progress file.

Acceptance: interrupted workflow before apply, rollback during apply, interruption after apply but before verification/save, stale source/target on resume, repeated operation without duplicate ledger growth, and visibility from both client paths after close/reopen. Do not port real working binaries as the acceptance fixture.

### WP11 — Return code after retyping/prototype changes

Initial supported operations: `variables(action=retype|set_prototype)`, `set_local_variable_type`, and `set_function_prototype`. Add `return_code=false` by default, bounded `max_chars` and a verification timeout. Structure-edit support follows only where an explicit affected function can be selected; do not automatically decompile every function affected by a shared type change.

Unify prototype application and qualified function lookup where practical. Remove duplicate automatic “Applied prototype” comments, or make an explicit comment option idempotent. Return the actual stored prototype rather than merely echoing input. Add bounded C text to structured `get_code` so workflows need not parse prose.

Separate mutation completion from verification: commit mutation and capture revision, release the writer guard, retain the selected program lease, then use the shared decompiler service. Return `mutation_status`, `verification_status`, selected identity/function, committed/observed revisions, stored prototype and optional bounded code. If the revision changes during verification, report `stale`; if decompilation fails, report `unavailable`. Do not mark the committed operation unexecuted or advise automatic retry.

Acceptance: real database and decompiler-only variable persistence, same-name signature update, idempotent comment behavior, returned stored prototype, bounded code, timeout/cancellation after commit, decompiler error and intervening GUI-like mutation. Returned code is inspection evidence, not a claim of semantic equivalence.

Deliver a focused deep-function skill using decompile → selected edit with `return_code` → inspect → save. Its core instructions and recovery rules come from the shared guide.

### WP12 — Package Claude, Grok and shared references

Claude deliverables:

- Root `.claude-plugin/marketplace.json` referring to the plugin directory under `claude-code-integration/`.
- Versioned `.claude-plugin/plugin.json` and `.mcp.json` within that plugin; preserve name and server key `ghidrassist` to avoid needless prefix changes.
- Porting and deep-function skills with tested descriptions, argument hints, architecture references and scoped tool guidance. Project operations remain a reference, not a fourth skill.
- Validate source/target paths with spaces and `#`; if positional quoting does not work in the installed client, use explicit skill input fields or conversational resolution rather than assuming a new ID encoding.
- Retire broken legacy hooks and one-off scripts after recording the native-tool replacements and moving genuinely useful architecture notes into references.

Grok deliverables:

- `grok-integration/config.example.toml`, `docs/GROK_INTEGRATION.md`, and a thin discoverable skill/reference wrapper using the installed client's supported location.
- Validate `[mcp] max_output_bytes`; start the example at 131072 bytes if supported. Document spill-file recovery and incomplete JSON handling. Do not reduce the existing tool timeout simply by copying the old example.
- Teach `search_tool` → `use_tool`, canonical family searches, generic versus BSim task identifiers, native preview/apply and separate save domains. Do not copy the Codex 27-tool allowlist.
- Do not add an active project `.grok/config.toml` until config precedence has been verified; when added, preserve user/server settings rather than replacing global configuration.

Shared packaging decisions:

- Version client packages explicitly and publish the minimum tested server/client versions. Detect missing new arguments/contracts and provide a clear upgrade message; do not silently run a degraded mutation workflow.
- Ship Java/runtime assets and the operating guide in the extension ZIP. Distribute client plugins separately from the repository; explicitly exclude client integration directories and local test/evidence state from the runtime ZIP.
- Preserve existing Codex wrapper guidance and validate its catalog names. Core text comes from WP04; no global installed skill/config is silently replaced.
- Update README installation/workflow links, catalog audit, task contracts and client comparison so obsolete claims point to this plan and final validation evidence.

Acceptance: actual client install/discovery, expected prefixes, instruction visibility, skill path parsing, structured/text result handling, spill recovery, long-task completion and disposable porting/deep-function flows. Record tested client versions instead of claiming universal resource, prompt, allowlist or timeout behavior.

### WP13 — Integrate, package and verify the release

Run the coordinated test suite once all packages integrate; rerun failures and affected tests after fixes. Build the extension, validate declared schemas and aliases, check runtime dependency JARs, client manifests and packaged guide text. Check ZIP contents against the explicit packaging decision.

Perform isolated GUI and project-bound headless smoke tests, then actual Claude/Grok workflow tests on disposable copies. Include Codex contract compatibility. Record skipped external BSim/shared-repository checks as unverified; do not represent fixtures as remote-service validation.

Prepare a versioned archive, source manifest, dependency list, validation report and release notes describing changed preservation/rollback defaults and new opt-in fields. Installation is a distinct release action: preserve a previous extension backup and existing project state, drain owned work, install the built artifact and restart through the appropriate workflow. Verify loaded runtime identity and discovery after restart. Do not infer completion from a copied ZIP.

Rollback: restore the prior extension/client package if necessary and verify its loaded identity. Extension rollback does not undo annotations already saved to programs; use disposable fixtures for release tests and existing project history/backups for any separate data rollback. Never promise reversible data migration merely because the plugin can be downgraded.

## 5. Compatibility contract

| Surface | Planned behavior |
| --- | --- |
| Existing names/aliases | Retained; descriptions point to canonical tools. |
| Capabilities | Full default retained; explicit compact mode added. |
| Program listing | Structured paging added; targeting guidance corrected; inventory changes explicit. Document prose changes. |
| Program IDs | Opaque; never truncate or split. Colliding mutable instances fail selection. |
| Static annotations | Remain conservative for mixed tools; execution traits are separate. |
| Task API | Existing metadata wait/status path retained; result-bearing wait and inline read completion added. Completion/submission schemas cover both. |
| Task retention | New finite queue/history/result limits with explicit busy/expired/too-large outcomes. Operation success is independent of payload retention. |
| Results | One complete JSON text fallback plus structured content where supplied; no client-only envelope. |
| Transfer policy | Analyst names/signatures preserved by default; explicit replacement and whole-call rollback documented as behavior changes. |
| Preview tokens | New workflows use them; stale supplied tokens rejected. Direct calls still validate immediately before apply. |
| Matching | Unsupported masked modes fail explicitly; raw-byte mode retained. Supported architectures are backed by fixtures. |
| `return_code` | Opt-in; mutation and verification outcomes reported independently. |
| Prompts/resources | Existing surfaces retained. No prompt rewrite or template removal. |

## 6. Release evidence matrix

| Area | Required evidence | Release blocker |
| --- | --- | --- |
| Dispatch/lifecycle | Read/write latch tests, aliases, cancellation, consumer ownership, shutdown | Any premature release, duplicate execution or mutation bypass |
| Identity | Duplicate names/instances, paths/Unicode, closed target, pages | Wrong target or silent collision selection |
| Discovery/output | Encoded byte measurements, complete JSON, cursors, oversized row | Invalid JSON, silently incomplete output or truncated IDs |
| Tasks | Saturation, rejected admission, inline/async parity, expiry | Leaks, lost outcome state or false cancellation |
| Transfers | Staged parse, provenance preservation, preview/apply parity, rollback and reopen | Reported state differs from committed state |
| Matchers/VT | Architecture positives/negatives, ambiguity, cancellation, stable review pages | Unsupported masks accepted or capped scan reported unique |
| Ledger | Atomic applied marker, verification transition, persisted resume | False verified/durable state |
| Deep function | Persisted edit, returned code, failure after commit, revision race | Applied mutation reported as rolled back/unexecuted |
| Clients | Tested versions, prefix/config/skill discovery, two end-to-end workflows | Package cannot perform its advertised workflow |
| Distribution | Suite summary, dependency/ZIP audit, installed and loaded hashes | Loaded runtime cannot be tied to the tested artifact |

## 7. Decisions resolved during implementation

These are bounded verification tasks with explicit fallbacks, not reasons to postpone unrelated work:

| Question | Resolve in | Default/fallback |
| --- | --- | --- |
| Which mixed read actions invoke expensive native work? | WP02 timing fixtures | Keep cancellable task capability; remove writer guard only for verified read actions. |
| Does a 500 ms inline window materially reduce calls? | WP05 benchmark | Ship configurable window; use zero if latency/throughput evidence is unfavorable. Result-bearing wait still reduces calls. |
| Can decoded operand masks preserve discriminating bits on each architecture? | WP08 fixtures | Reject unsupported mode; use native VT/available BSim or explicit raw bytes. |
| How does installed Claude parse paths and surface instructions/resources? | WP12 client smoke | Explicit selector input/resolution and packaged reference; no prompt rewrite. |
| Which Grok keys/skill paths and byte accounting apply? | WP12 client smoke | Ship only verified config; document actual spill recovery and tested version. |
| Do budgets need tuning for real supported workflows? | WP05/06 measurements | Keep limits configurable; never fix truncation by silently dropping semantics. |
| Are external BSim/shared repository environments available? | WP13 | Report unverified external coverage; do not claim it passed. |

## 8. Deferred work

Defer all seven MCP prompt rewrites, prompt completion, resource subscriptions, new protocol transport/Tasks extension, per-client server catalogs, a general skill generator, full generic-task restart recovery, a new inventory join/region-probe orchestration tool, schema conversion of every remaining tool, and forced-interaction hooks/metadata. Revisit after the two workflows have measured end-to-end evidence.

Keep `return_code`, PORT provenance, basic queue/result bounds and thin client packaging in scope; these are not deferred with the larger projects above.

## 9. Implementation checklist

- [x] WP01 Baseline, conformance harness and `CLAUDE.md`
- [x] WP02 Action-aware dispatch, aliases and timings
- [x] WP03 Compact discovery and collision diagnostics
- [x] WP04 Shared operating guide and packaging check
- [x] WP05 Result-bearing wait, bounded task lifecycle and inline reads
- [x] WP06 Selected output budgets and workflow descriptors
- [x] WP07 Transfer plan, validation, policies and truthful outcomes
- [x] WP08 Listed instruction-qualified matcher fixtures and schemas
- [x] WP09 VT names, filters and stable pages (native contract coverage)
- [x] WP10 PORT ledger and persisted native/disposable HTTP workflow
- [x] WP11 Post-mutation code and native deep-function workflow
- [ ] WP12 Packages and core client workflows passed, including shared PORT visibility; broad spill/invocation acceptance remains in client reports
- [ ] WP13 Integrated suite/archive/headless checks passed; user-GUI installation and external-service gates remain

Checked entries represent the tested server/fixture scope described in final validation. Unchecked entries are remaining environment/client acceptance, not missing core implementation. Do not mark them complete by substituting a unit or headless fixture for actual client/GUI behavior.
