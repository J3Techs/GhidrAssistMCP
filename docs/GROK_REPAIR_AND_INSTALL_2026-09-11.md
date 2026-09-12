# Grok review repairs and installation

The supplied review of commit `5b3a058` was reconciled against the existing modernization work, then repaired in coordinated mutation, query, lifecycle and context tracks. Existing public tool names are preserved. The [preparation document](GROK_REVIEW_FIX_PLAN_2026-09-11.md) records the original assessment; this report supersedes its pending-fix status.

## Review disposition

| Report items | Final behavior and evidence |
| --- | --- |
| 3, 4, 16 | Earlier fixes retained: cancellation bypasses the mutation lock without pretending to be read-only; exact resource selectors; correct task error flags. Existing task and HTTP regression tests remain. |
| 6, 7, 8, 10, 11, 12 | Exact target identity and scoped target consumers; real variable retyping; selective code-unit clearing; atomic function/region rollback; explicit type conflict policy; failed rebasing prevents import save/open. See [mutation evidence](GROK_FIX_MUTATIONS.md). |
| 2, 5, 2.3-retry, 2.11 | Actual script execution owns cancellation and locks until settlement; GUI stopping/draining preserves ownership; generic synchronous calls, resources and prompts are tracked; BSim work retains queued/running consumers and supports per-backend drain and retry; headless launchers retain their caller's project until work stops. See [lifecycle evidence](GROK_FIX_LIFECYCLE.md). |
| 14, 15, 20, 21 | Honest unreadable-byte output; emitted text/row limits and bounded aggregate graphs; nested folder traversal; consistent qualified/containing function lookup and exact matcher program selection. See [query evidence](GROK_FIX_QUERIES.md). |
| 9, 13, 17, 19; omitted arguments | Typed temporary options restored after analysis stops; cancelled batches stop advancing; bound BSim project wins over global state; diagnostics do not create GUI managers; process-owned authentication; omitted arguments normalized. See [context evidence](GROK_FIX_CONTEXT.md). |
| 1, 18 and remote-bind policy | Existing intentional local script/file capabilities retained with accurate annotations. Loopback binding is mandatory by default; remote binding requires explicit operator opt-in. Credential installation requires explicit process configuration. See [deployment policy](DEPLOYMENT_TRUST.md). |
| Prototype hypothesis | Removed unnecessary EDT dependency; signature and reference comment share successful transaction; failures are flagged and preserve prior state. |
| Other hypotheses | No unproven issue is claimed reproduced or fixed. Shared backend state is documented product behavior. VT's pre-apply transaction guard must not roll back another writer's work. Snapshot-consistent reads during arbitrary concurrent GUI analysis and hard regex CPU bounds remain outside the guarantees of these repairs. |

## Compatibility changes

- Creation with incompatible existing types requires explicit `conflict_policy=replace`.
- Function/region batches report rollback after a mutating failure instead of silently keeping earlier partial writes.
- Range clearing uses half-open boundaries and rejects boundaries that bisect selected code units.
- Default script execution is off EDT. A cancellation request can remain pending until noncooperative native/script execution exits.
- The project-bound headless launcher defaults to waiting and rejects `wait=false`; standalone embedded callers retain their nonblocking API and responsibility for project lifetime.
- Remote listeners and BSim authentication overrides require the explicit startup configuration described in deployment policy.
- Query consumers must respect published limits, partial/error details and truncation markers.

## Validation and installation

The coordinated suite against Ghidra 12.0.3 passed **243 tests**, with **2 environment-gated external BSim tests skipped**, **0 failures** and **0 errors** across **65 suites / 245 tests**. The skipped cases require PostgreSQL and Elasticsearch services. The first integrated run exposed six old BSim fixture cleanup failures; all context callers were audited, five test classes now close their contexts, and the complete suite passed on rerun. Production context construction already used try-with-resources.

The final runtime uses MCP SDK **2.0.1**, Jetty **12.1.13** and Jackson **2.21.1**. It negotiates protocol revisions through **2025-11-25**. Custom asynchronous task tools remain distinct from the MCP Tasks extension; the later July 2026 stateless protocol is not advertised as supported. The generated catalog contains **145 registered tools**, **142 enabled by default**, and **12 output schemas**. Project-bound headless mode additionally disables three GUI/session tools.

Build compilation uses the private JDK 25 toolchain; the installed-runtime smoke uses Java 21. The repository skill validates, all 27 names in the optional Codex catalog resolve, and `git diff --check` passes. The extension packages only the resolved current dependency set, excluding obsolete local `lib/` jars.

Deployment paths for this run:

- Ghidra: `C:/Users/JResp/Desktop/ghidra_12.0.3_PUBLIC`
- Installed extension: `C:/Users/JResp/AppData/Roaming/ghidra/ghidra_12.0.3_PUBLIC/Extensions/GhidrAssistMCP`
- Previous-installation backup: `C:/Users/JResp/Documents/GhidrAssistMCP-install-backup-20260911-182322-before-grok-fixes`
- Archive: `dist/ghidra_12.0.3_PUBLIC_20260911_GhidrAssistMCP.zip`
- Per-run evidence: `build/install-smoke-grok-fixes-20260911/` contains the test totals, archive/installed-file verification, loaded runtime capabilities, and final `install-receipt.json` with hashes and shutdown result. Consult the receipt for installation completion, rather than inferring it from this packaged report.

No live user program, remote BSim service, credentials or shared repository is used by the repair tests. The installed-server smoke check uses a disposable headless project. Source changes remain uncommitted in the working tree.
