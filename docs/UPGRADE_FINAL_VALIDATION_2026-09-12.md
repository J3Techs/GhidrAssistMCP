# Workflow upgrade: final integration evidence

The server upgrade passes its integrated checks and packaged headless smoke tests. The extension loaded in the user's existing GUI has not been replaced. The [implementation plan](MCP_UPGRADE_IMPLEMENTATION_PLAN.md), [release notes](UPGRADE_RELEASE_NOTES.md) and [gate matrix](RELEASE_GATE_AUDIT.md) distinguish delivered behavior from remaining environment-specific acceptance.

## Team and review

The requested three-agent Luna team worked on discovery/client packaging, dispatch/transfer integrity, and query/task bounds. GrokMCP ran a separate three-agent team for transfer/matcher/VT concerns, followed by a native architecture-qualification team. Root integrated the changes, challenged unsupported claims, fixed inter-team API conflicts and ran all Gradle verification.

The second Grok run was `5e3a1ffc-311a-4f5c-a9cc-f81b07ca73df` in persistent session `64411d14-423b-4514-b95d-5c1dc25a996e`. It ended successfully with `cleanup_verified=true`, approximately 23.1 minutes and 401 tool events. Those are orchestration observations, not a comparable cost benchmark. All delegated write scopes were released before final integration. The earlier run is recorded in [the first team report](UPGRADE_TEAM_VALIDATION_2026-09-11.md).

Review found and corrected: missing shared-decompiler wiring for prototype verification; a missing build-fingerprint schema field; unsafe default byte-window behavior; scan/output budgets that were incomplete; fixed-width VLE assumptions; architecture tests that could pass without decoding the claimed instruction; and prototype-name guidance that ignored Ghidra's default-origin naming rules. Tests now require actual x86, ARM, Thumb and VLE instruction fixtures. Compound memory operands retain register fields. VLEALT remains unsupported pending its own qualification.

## Build and artifact identity

Command: `gradlew.bat -PGHIDRA_INSTALL_DIR=<Ghidra 12.0.3 PUBLIC> check buildExtension writeUpgradeFixtureArgs --console=plain`.

- Final log: `build/upgrade-final-check6.log`, successful in 27 seconds.
- JUnit: **369 tests, 367 passed, 0 failures, 0 errors, 2 skipped**. The skips are `BsimExternalBackendLifecycleTest`; external service validation is not claimed.
- Build JVM: JDK 25.0.4.1+1; emitted class major 65 (Java 21). Runtime fixture: Ghidra 12.0.3 PUBLIC, MCP SDK 2.0.1.
- Archive: `dist/ghidra_12.0.3_PUBLIC_20260911_GhidrAssistMCP.zip`.
- Archive SHA-256: `fb7fec6c58e40d4a79e6a45abe97c7e042d7cfe45ef97d470ffb393857992215`.
- Runtime JAR SHA-256: `3490f217a6328c9679c6c4096c215b4772d8ce16d45782e68cd7ccbf25213208`.
- Runtime source fingerprint: `4d4a53463f40fab847c6331be2bf182594fcaeebff73d26c4e7c8d53689b9be0`.

The source fingerprint covers sorted relative paths and raw contents of all `src/main` files, `build.gradle` and `extension.properties`. Build provenance records base revision `2381830` with dirty state because this is the tested pre-commit snapshot. It does not pretend that base revision alone identifies these changes. Later documentation edits do not change the runtime source fingerprint.

`validation/release_evidence.py` verified the packaged guide, Java class version, client/temporary-file exclusions and source fingerprint, and captured every dependency JAR hash plus JUnit suite hashes in ignored local evidence `build/upgrade-validation/final-release.json`. Claude/Grok packages remain repository distributions rather than installed global client configuration. This final evidence document was written after the archive and accompanies it through the repository.

## Loaded packaged-runtime checks

The final fixture loaded `GhidrAssistMCPBackend` from the extracted release JAR, with packaged dependencies and Ghidra libraries; it excluded development main classes/resources and Gradle dependency caches. `ready.json` recorded the JAR code source and the same source fingerprint as the archive.

- Twelve HTTP conformance checks passed: initialization and notification, tools, compact capabilities, bounded discovery/search, resources, exact fixture code, missing-selector and missing-task errors. Report: `build/upgrade-validation/final-conformance-v2.json`.
- Nine structured decompiler calls returned actual completed C text. First observed: 362.17 ms; warm median: 3.40 ms; complete response bytes: 36,253. This tiny fixture is not a production throughput or large-function claim. Report: `final-benchmark-v2.json` in the same directory.
- The public PORT workflow passed against the final archive: obtain exact source fingerprint, dry-run a rename/prototype, apply with the reviewed token, observe `applied_unverified`, verify fingerprints/revision, save, rediscover the changed ID, release/reacquire the MCP target consumer, and confirm the verified checkpoint and unchanged source. Report: `final-port-workflow.json`.
- The fixture launcher retains an owner consumer until shutdown, so that HTTP close/open check is consumer reacquisition, not proof that the database object was destroyed. `PortLedgerPersistenceIntegrationTest` independently saves, fully closes the project/objects and reopens the database from disk, including stale-source rejection and persistent verified state.

## Actual clients

Claude Code 2.1.269 passed plugin validation and isolated discovery with the expected `mcp__ghidrassist__` prefix. Its captured 15-turn mutation trace completed native prototype application with returned C, save, exact-ID rediscovery and MCP close/reopen. It correctly encountered the stale pre-save versioned ID and recovered through discovery. Native signature application changed a default-origin symbol; a separate native test proves an analyst name is retained.

The client-specific reports are [Claude integration](CLAUDE_INTEGRATION.md) and [Grok integration](GROK_INTEGRATION.md). They record the final client attempts and limitations; successful server fixtures must not be substituted for an uncompleted client workflow. Client traces are local evidence and are not committed with authentication/session material.

Grok 1.0.30 also completed native prototype application with bounded returned C and async save, followed by exact-ID close/reopen and stored-prototype confirmation. It used an isolated project config under the already trusted repository, disabled unrelated MCP connections and preserved global configuration. The captured Grok JSON contains its final step-by-step report (preceded by startup warnings); server logs independently record those tool invocations. It is not a raw complete MCP wire transcript. Claude's capture is a streaming JSONL transcript. These client runs used preceding fixture builds; the final packaged build subsequently clarified the prototype tool's name-preservation description without changing that operation's implementation.

Local evidence hashes:

| Capture | SHA-256 |
|---|---|
| Claude round-two mutation JSONL | `9b33498faf0a74f5000cef21e1cb3b265616a83a9d10a99ae562040036c36891` |
| Grok packaged mutation report | `fd2484ddc4f14a4bec6290e052837706f26a9989f347844fa3869ddad0069ea1` |
| Grok packaged close/reopen report | `6d78caa7a4ce4540c32051256649a6bac8bc3c134c36dafad2e23ed0e77cd565` |
| Claude packaged PORT JSONL | `c810c0e29ae4343c54aebc7097fd52ddf8e102ada378de4146207239ac402646` |
| Grok shared PORT read report | `ed217b8023f5c36b337387650c5b45f2d307c37db4d4769adcc81d8f37d42bb7` |

Cross-client PORT acceptance also passed. Claude first observed a truthful preserved/no-op outcome on the existing analyst-named target, with no checkpoint created. A fresh preview with explicit replacement policies then committed one selected row, verified the checkpoint, saved and rediscovered target version 3, and recovered the verified marker after consumer close/reopen. Source fingerprint/revision stayed unchanged. Grok independently discovered that exact target and read the same operation ID, verified checkpoint and matching current destination fingerprint without mutation. Source and destination fingerprints need not equal each other: each is compared against its own recorded state.

After validation, all root-owned disposable HTTP servers/project consumers were closed through their stop-file lifecycle and the temporary isolated client configurations were removed. Saved fixture/evidence files remain under ignored build/temp directories. The core upgrade was committed and pushed to default branch `master` as `da33ce3`; client evidence is recorded in the documentation follow-up.

## Remaining release boundaries

The user GUI at port 8080 still runs its earlier extension. Its open programs include unsaved dirty/read-only state that cannot simply be saved, so no forced close/restart, global installation or replacement of that state was performed. This does not block committing and pushing the reviewed source to the default branch.

External BSim/shared-repository services, exhaustive instruction-family coverage, production contention tuning and every possible client spill/recovery path remain unverified. PORT listing bounds returned rows/bytes but can iterate many unrelated NOTE bookmarks. Region's optional legacy function creation is outside the recommended reviewed porting flow. These are explicit boundaries, not silently green release gates.

Deferred design work remains unchanged: seven prompt rewrites, protocol Tasks migration, subscriptions, per-client catalogs, generic task restart recovery and unattended mutation hooks.
