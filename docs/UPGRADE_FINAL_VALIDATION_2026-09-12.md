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

## Remaining release boundaries

The user GUI at port 8080 still runs its earlier extension. Its open programs include unsaved dirty/read-only state that cannot simply be saved, so no forced close/restart, global installation or replacement of that state was performed. This does not block committing and pushing the reviewed source to the default branch.

External BSim/shared-repository services, exhaustive instruction-family coverage, production contention tuning and every possible client spill/recovery path remain unverified. PORT listing bounds returned rows/bytes but can iterate many unrelated NOTE bookmarks. Region's optional legacy function creation is outside the recommended reviewed porting flow. These are explicit boundaries, not silently green release gates.

Deferred design work remains unchanged: seven prompt rewrites, protocol Tasks migration, subscriptions, per-client catalogs, generic task restart recovery and unattended mutation hooks.
