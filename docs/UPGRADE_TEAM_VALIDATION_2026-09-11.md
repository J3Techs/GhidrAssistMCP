# Upgrade team implementation and validation

This is the first integration checkpoint. The continuation adds PORT persistence, native post-edit decompilation, request timings, instruction-qualified masks and packaged-runtime checks. Current results are in [final validation](UPGRADE_FINAL_VALIDATION_2026-09-12.md).

Status: the bounded team implementation is integrated and validated. Full release acceptance remains open; see the [implementation plan](MCP_UPGRADE_IMPLEMENTATION_PLAN.md) for the remaining gates.

## Ownership

The user requested a Luna team and a separate GrokMCP team. Three `gpt-5.6-luna` agents handled discovery/client packages, action dispatch/post-mutation verification, and query/task bounds. Root integrated and reviewed their changes and ran Gradle. GrokMCP ran its own three agents on transfer integrity, architecture-qualified matching, and native Version Tracking queries. Their writable files were kept separate from Luna's assignments.

Grok correlation: `0ea2b557-dfa6-4d98-bc37-602dd1b0b040`; persistent session: `64411d14-423b-4514-b95d-5c1dc25a996e`. Source baseline: `2381830`; the user's existing README change and review documents were preserved.

Grok completed with `cleanup_verified=true` and no running children. Its parent ran for about 36.5 minutes, reported 12 changed files and 481 tool events. These are orchestration metrics, not comparable token/cost measurements against Luna. Inside Grok, a nested MCP launch hit that connection's path restriction; its parent successfully used three native TUI subagents instead. See the [Grok handoff](GROK_TEAM_UPGRADE_REPORT.md).

## Integrated interaction work

- Argument-aware read/mutation dispatch and alias delegation. Read actions of variables, structs, comments and types avoid the global writer guard; static protocol annotations remain conservative.
- Compact capability discovery and bounded `list_binaries` pages with opaque IDs, inventory revisions and collision diagnostics. Complete encoded discovery results are checked before returning a page.
- One canonical server initialization guide with packaged Claude/Grok references. `syncOperatingGuides` updates copies; `checkOperatingGuides` rejects drift.
- A configurable 500 ms read completion window (0–1000 ms), single task submission, task fallback, preserved interruption, and retryable queue rejection. This default is fixture-tested; representative live latency/throughput tuning remains pending.
- Optional complete results in `wait_task`, bounded independently from task retention. Four worker threads, 64 queued tasks, 4 MiB per retained result, 64 MiB aggregate retained payload, 1,024 terminal records and one-hour retention are the defaults. Retention measures encoded MCP results, not total JVM heap usage. Eviction does not change the operation outcome.
- Bounds and visible continuation/truncation for selected legacy queries. Text pages reserve a 20,000-character ceiling including footer space, leaving room for JSON escaping under the proposed 128 KiB client cap. These are not a claim that every catalog tool now has a structured schema or bounded total scan cost. Basic-block edge lists remain capped at 256 per direction.
- Opt-in `return_code` for prototype/retype operations. Verification happens after commit without holding the writer guard; results distinguish committed edits from stale/unavailable verification. Returned code is bounded without splitting UTF-16 surrogate pairs. The prototype path is shared by the variables family and the dedicated tool.
- Versioned Claude plugin/marketplace and thin Grok wrapper. Positional project paths are resolved once to exact IDs. The Grok configuration fragment remains inactive and requires client-version verification.

## Integrated transfer and matching work

- `bulk_transfer_labels` shares validation between preview and apply, parses against one bounded isolated type snapshot, preserves analyst names/signatures by default, supports explicit replacement and rejects stale supplied tokens. Invalid plans do not mutate. Native apply failures roll back the call; preview counts do not claim committed edits. Requests are capped at 500 rows and staging at 10,000 types.
- Byte and region matchers qualify language, endianness and VLE range context before applying legacy masks. Explicit raw-byte mode remains available. ARM/x86 callers must not rely on default `auto` masking. Byte scans return candidates and completeness/uniqueness evidence; string-anchor results use JSON serialization.
- `vt_matches` returns names, provenance and native scores, supports filters and stable pages, and binds paging to session plus source/destination revisions. The retained sorting window is capped at 5,000 entries; exhausted windows require narrower filters. Other VT mutation paths are preserved.

## Review findings and rework

Agent completion reports were treated as claims to verify. Luna's first pass required corrections for compilation, context-aware test expectations, asynchronous timing assumptions, missing prototype delegation, result byte accounting, post-commit function selection and suppressed truncation footers. A claimed task-result eviction fix was absent from the implementation and was completed by root. A claimed limitation in constructing decompiler result fixtures was resolved by inspecting the installed Ghidra API.

Root review of Grok's draft identified insufficient VLE context/endian qualification, preview rows counted as commits, unbounded VT paging windows and missing program revision binding. These were returned to Grok for correction before integration acceptance.

The combined 40-test transfer/matcher/VT run found seven failures: six valid applies were rejected by an overly strict transaction-description check, and one test used an obsolete architecture label. After those fixes, the full suite found two older assertions requiring unconditional name replacement; these were updated for the intentional new policy. Root also reordered transaction ownership and revision checks and added a deterministic race fixture proving stale MCP work cannot abort a foreign writer's edit.

## Validation evidence

The first focused interaction run passed 25 tests. The first full run exposed five test-contract/timing failures and these were corrected. A subsequent full run passed with two external BSim skips. Further changes are not covered by that intermediate result until the final suite below is recorded.

Final `check buildExtension`: **327 tests, 325 passed, 2 skipped, 0 failures/errors**. The skips require external BSim infrastructure. This includes the existing native VT integration tests and eight independent root ProgramDB transfer tests. Java/resource/test/build inputs did not change during the final run. `git diff --check` passed.

Toolchain: JDK 25.0.4.1+1 with Ghidra 12.0.3; generated classes target Java 21 (class-file version 65). The archive's nested server JAR contains the canonical operating guide byte-for-byte, and standalone client packages are excluded from the extension.

Artifact: [`dist/ghidra_12.0.3_PUBLIC_20260911_GhidrAssistMCP.zip`](../dist/ghidra_12.0.3_PUBLIC_20260911_GhidrAssistMCP.zip). Final hash, test totals, input fingerprints and build log are recorded in [`build/upgrade-validation/2026-09-11-teams/`](../build/upgrade-validation/2026-09-11-teams/). The archive is rebuilt after this report update so its packaged documentation reflects the validated result.

## Remaining release gates

- Complete PORT bookmark provenance in the transfer transaction and verify save/reopen and resumption on disposable programs.
- Qualify architecture-specific matching with real instruction/context fixtures; generic ARM/x86 relocation masks are not implied by architecture rejection guards.
- Measure live porting and deep-function workflows, large-result behavior and representative latency under contention.
- Install/smoke the client packages, verify actual tool prefixes, path parsing, instructions and spill recovery; verify Grok config keys and precedence.
- Validate the extension artifact, then install/restart and verify the loaded JVM separately when deployment is requested. No source/build result establishes that the running Ghidra instance changed.

No commit, client installation, Ghidra restart or live project mutation is claimed by this implementation run.
