# Release-gate status

The integrated suite passes 369 tests with two external-service skips (367 passed, no failures). The source-built archive also passed a fresh packaged-JAR headless conformance run. See [final validation](UPGRADE_FINAL_VALIDATION_2026-09-12.md) for artifact and client evidence. This supersedes the earlier provisional team matrix.

| Work package | Implemented and verified scope | Remaining acceptance boundary |
|---|---|---|
| WP01 baseline/conformance | Repeatable HTTP probe, source/JAR/dependency manifest, toolchain and test evidence | No universal client/protocol revision claim |
| WP02 dispatch | Action/alias traits, writer bypass tests, worker/lease lifecycle and request timings | Metrics measure server phases, not end-to-end model latency |
| WP03 discovery | Compact capabilities, exact IDs, collision diagnostics, stable inventory pages | Inventory changes invalidate cursors |
| WP04 guide | One canonical initialization guide and build-time copy checks | Client wrappers remain separate packages |
| WP05 tasks | Finite admission/retention, inline reads, result-bearing waits, cancellation tests | Process-local tasks do not resume across restart |
| WP06 bounds | Selected legacy pages, complete batch/inventory/matcher result budgets | Not a catalog-wide native-memory or scan-cost guarantee |
| WP07 transfer | Isolated prototype validation, preservation, preview revisions, rollback and fixture persistence | Explicit legacy region function creation is not part of the recommended port workflow |
| WP08 matchers | Real x86/ARM/Thumb/VLE positives and negatives, qualified decoded masks, bounded byte search | Only listed language/fixture families; no VLEALT/general architecture claim |
| WP09 VT | Names, provenance, filtering, revision-bound pages and bounded sorting window | External shared repository coverage not established |
| WP10 PORT | Atomic applied marker, fingerprint verification, idempotence, stale-source checks, save/close/reopen | One latest checkpoint per function; NOTE iteration cost is not strictly capped |
| WP11 deep function | Native backend/decompiler wiring, actual stored prototype, post-commit verification and persistence tests | Returned C is inspection evidence, not semantic equivalence |
| WP12 clients | Versioned wrappers; both clients completed prototype/save/reacquisition; Claude PORT apply and Grok shared-checkpoint visibility passed | General spill/recovery and all invocation forms remain unverified |
| WP13 release | Full suite, ZIP audit, loaded packaged-JAR identity, disposable conformance | User GUI install/restart remains pending unsaved project state; external BSim tests skipped |

The running user GUI was not replaced. Its open programs include dirty read-only state that cannot simply be saved; restarting would require a deliberate state-preservation decision. The reviewed archive can be committed and pushed independently of that installation gate.

Intentional deferrals remain: seven prompt rewrites, new protocol Tasks, subscriptions, per-client catalogs, generic durable job recovery, automatic function creation from weak matches, and unattended mutation hooks.
