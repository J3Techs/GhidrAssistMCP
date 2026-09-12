# Grok team upgrade report (WP07–WP09 bounded slice)

Prepared 2026-09-11. Parent: Grok 4.6 in this session. Codex/root owns Gradle, backend/task files, and final suite execution. This team did not run Gradle, git commit/reset/stage, live MCP/Ghidra, or WP10 ledger/workflow work.

Root integration follow-up: the final suite and archive passed after correction of the reported test failures and transaction-race handling. See the [final team validation report](UPGRADE_TEAM_VALIDATION_2026-09-11.md); the unexecuted-test notes below describe the Grok handoff, not the final repository status.

## Child agents

Codex successfully launched this parent through GrokMCP in the project workspace. Inside that Grok session, an attempt to launch nested agents through its separate GrokMCP connection failed with `PATH_NOT_ALLOWED` because that connection allowed only `C:\Users\JResp\Desktop`. The parent used its native TUI subagent facility instead; all three children settled:

| ID | Scope |
| --- | --- |
| `01a09381-2446-73b0-bb6b-a36f71ec60ad` | A transfer: `BulkTransferLabelsTool.java`, `TransferPlanSupport.java`, `TransferPlanContractTest.java` |
| `01a09381-2446-73b0-bb6b-a37553e3c7cc` | B matcher: `FunctionByteMatcherTool.java`, `StringAnchorMatcherTool.java`, `BulkRegionTransferTool.java`, `MatcherContracts.java`, `MatcherArchitectureContractTest.java` |
| `01a09381-2446-73b0-bb6b-a384ead91789` | C VT: `VTTool.java`, `VTSupport.java`, `VTMatchQueryContractTest.java` |

Parent reviewed diffs for disjoint ownership, then applied bounded correctness fixes (compile, fail-closed VLE, staging snapshot, dry-run counts, VT paging, transfer validation/transaction). Root-owned `src/test/java/ghidrassistmcp/tools/BulkTransferIntegrityProgramDbTest.java` was not edited.

## Changed paths

- `src/main/java/ghidrassistmcp/tools/BulkTransferLabelsTool.java`
- `src/main/java/ghidrassistmcp/tools/TransferPlanSupport.java`
- `src/test/java/ghidrassistmcp/tools/TransferPlanContractTest.java`
- `src/main/java/ghidrassistmcp/tools/MatcherContracts.java`
- `src/main/java/ghidrassistmcp/tools/FunctionByteMatcherTool.java`
- `src/main/java/ghidrassistmcp/tools/StringAnchorMatcherTool.java`
- `src/main/java/ghidrassistmcp/tools/BulkRegionTransferTool.java`
- `src/test/java/ghidrassistmcp/tools/MatcherArchitectureContractTest.java`
- `src/main/java/ghidrassistmcp/vt/VTTool.java`
- `src/main/java/ghidrassistmcp/vt/VTSupport.java`
- `src/test/java/ghidrassistmcp/vt/VTMatchQueryContractTest.java`
- `docs/GROK_TEAM_UPGRADE_REPORT.md`

README and existing/untracked review docs were not edited.

## Implemented

### WP07 transfer
- Shared plan for dry-run and apply; prototype parse independent of rename.
- Isolated C parse via **one** bounded `StandAloneDataTypeManager` snapshot per request (`MAX_STAGED_TYPES=10000`), reused across rows (`MAX_TRANSFERS=500`).
- `FunctionDefinitionDataType(FunctionSignature, DataTypeManager)` uses the staging manager.
- `name_policy` / `signature_policy` default `default_only` (BSim-style DEFAULT-origin only); `replace` is explicit.
- Strict argument types: `dry_run="true"` and non-boolean/non-string policies/tokens error (no silent coerce). Direct apply still validates; stale `preview_token` fails before mutation.
- Whole-call rollback; enclosing transaction rejected **before** `startTransaction`.
- **No `Program.lock` on the target** (would deadlock `startTransaction` via `DomainObjectLockedException` / `tryForeverExceptionHandler`). After `startTransaction`: recheck `modificationNumber`; if a foreign subtransaction is present, set `commit=true` and return without edits (do not abort a foreign writer).
- Dry-run counts: `committed=0`, distinct `would_commit`. Output schema declared.

### WP08 matchers
- Fail-closed VLE masks: proven PowerPC, **BE**, language variant `:VLE` (not substring / not LE / not e200+register presence).
- `rangeVleContext`: start/end required **before** no-register `VLE_ON`; with a `vle` context register, intervals must **cover start through end contiguously**; gaps → `UNKNOWN`.
- `mask_mode=none` raw bytes; unknown modes error; auto/aggressive do not silently fall back to exact bytes.
- Byte matcher: executable-memory scans, `TaskMonitor`, structured candidates, no uniqueness from a cap.
- Region transfer uses the same architecture guard on offset detection **and** verification; matching non-VLE uses exact bytes.
- String matcher: real Jackson JSON, full vs preview anchor, honest uniqueness.

### WP09 VT
- `vt_matches` rows: names (JSON null if missing), name `SourceType`, correlator, match-set provenance; existing addresses/status/native scores kept.
- Filters: `match_set_id`, `status`, `min_score` (native similarity).
- Stable sort: similarity desc, confidence desc, set id, addresses, **scanIndex** (duplicate keys do not collapse).
- Paging: `MAX_PAGE_WINDOW=5000` on `offset+limit`; exact integer parse (no double/`intValue` wrap of `Long.MAX_VALUE`).
- Continuation: `has_more` + `next_offset`.
- Paging identity tuple: `session_revision`, `source_program_id`/`source_revision`, `destination_program_id`/`destination_revision`. GUI name edits change program revision even if the session does not. Output schema only on `vt_matches`. Other VT operations unchanged.

## Deferred (explicit, not expanded)

**WP10 PORT ledger and porting workflow (not this slice):**
- NOTE bookmarks in category `PORT` with versioned metadata (operation ID, source persistent identity/address, fingerprints, matching method, verification state).
- `applied_unverified` in the transfer transaction; later `verified` only after identity/revision checks in a separate transaction.
- Resume from persisted program ledger, not process-local task IDs or client JSON.
- Porting skill workflow steps 1–6 (capabilities, remaining scope, candidates, preview, apply+PORT, independent saves).
- Interrupted-workflow / reopen acceptance fixtures.

Also deferred here:
- Generic instruction-aware masks (ARM/Thumb/x86) and architecture ProgramDB mask fixtures.
- `getFunctionContaining` for interior VT names.
- `bulk_region_transfer` transfer-plan unification (WP07 mentioned it; region tool only got architecture guards).
- Save/reopen PORT/VT markup (existing `VTNativeIntegrationTest` not re-run).
- Prompt rewrites, MCP Tasks conversion, client packaging (root/Codex).

## Tests written but not run

Gradle was forbidden while teams share the tree. Root should run:

```text
gradle test --tests ghidrassistmcp.tools.TransferPlanContractTest --tests ghidrassistmcp.tools.MatcherArchitectureContractTest --tests ghidrassistmcp.vt.VTMatchQueryContractTest --tests ghidrassistmcp.tools.BulkTransferIntegrityProgramDbTest --tests ghidrassistmcp.tools.BulkTransferLabelsProgramDbTest --tests ghidrassistmcp.vt.VTNativeIntegrationTest
```

Then the full suite.

- `TransferPlanContractTest`: helper contracts + ProgramDB cases (child). Root `BulkTransferIntegrityProgramDbTest` covers preservation, same-name prototype, failed dry-run isolation, zero committed preview, stale token, invalid `dry_run`, explicit replace.
- `MatcherArchitectureContractTest`: none-on-x86/ARM, reject LE/e200/unknown context, accept only proven BE VLE + `VLE_ON`.
- `VTMatchQueryContractTest`: names/nulls, filters, stable order, distinct sets, revision invalidation, window cap, exact ints, scanIndex uniqueness.

## Parent review notes / compile risks

- First compile log errors: `FunctionByteMatcherTool.java:94` `Map.of` >10 pairs (fixed via `LinkedHashMap`); `TransferPlanSupport.java:163` `FunctionDefinitionDataType` constructor (now `(definition, staging)`).
- `BulkTransferLabelsProgramDbTest` still expects default overwrite of USER_DEFINED names; new default is `default_only`. Integration ask: pass `name_policy=replace` or update that existing test (this team must not edit it).
- Post-`startTransaction` revision equality: if this Ghidra build increments `modificationNumber` on start, apply would abort as stale. Root fixture owns that proof.
- `ApplyFunctionSignatureCmd` 7-arg + `FunctionRenameOption.NO_CHANGE` assumed present (Ghidra 12).
- Isolated snapshot of large type catalogs can fail at 10k types.

## Integration asks

1. Run the focused tests above, then full suite. Do not infer pass from this report.
2. Update `BulkTransferLabelsProgramDbTest` for `default_only` if those assertions fail.
3. Default `mask_mode=auto` now errors on ARM/x86; callers must use `none`, native VT, or BSim.
4. `function_byte_matcher` is long-running (async submission union).
5. WP10 ledger/workflows remain for a later package.
6. Backend/task/wait/guide files stayed with Codex/root.

## Post-integration fixes (40 tests / 7 failures)

- Transfer own-transaction guard matches the **exact** `startTransaction` string and Ghidra native `": " + description` prefixes. Unique per-call description: `MCP bulk_transfer_labels <nanoTime>`. Foreign writers still return with `commit=true` and no edits. No target `Program.lock`.
- Matcher `supportedModeTable` test recognizes architecture `PowerPC BE VLE`.
- Byte matcher `blocks_scanned` counts entered blocks, not the pre-scan list size.
- `VTSupport.offset()` restored to `0..Integer.MAX_VALUE` for markup and other VT tools. Match paging cap is `pageWindowCap` only. When more matches exist but `next_offset+1 > 5000`, `next_offset` is JSON null, `has_more` is false, `page_window_exhausted` / `requires_filter` are true.

Children are settled. Scopes released for root's suite rerun. This team did not run Gradle.
