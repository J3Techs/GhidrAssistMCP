# Headless auto-analysis transaction fix

Runtime revision: `7368266f113e384d86b6bc0767ad3f454d47e05f`.

The FORD service logged `db.NoTransactionException: Transaction has not been
started` during native analyzers and `StoredAnalyzerTimes` persistence.
`AnalysisUtils.runAnalysis` called the synchronous `AutoAnalysisManager`
without owning a database transaction. Ghidra catches some analyzer exceptions,
so earlier MCP tasks could report completion despite incomplete analysis.

The fix owns a transaction when no analysis PluginTool is available, covering
scheduling, execution, waiting and cleanup. It follows Ghidra 12.0.3's native
`HeadlessAnalyzer`: completed work remains in memory on cancellation/failure,
temporary per-call options are restored, and saving remains explicit.

## Validation

- Native ProgramDB regression tests reproduced the failure before the fix in
  full, changes and mid-analysis cancellation cases; all three pass afterward.
- Full Gradle check: 378 tests, 376 passed, two external BSim tests skipped.
- Packaged MCP fixture: full analysis, changes analysis and save passed.
- Installed native Java 21 launcher: the same operations passed on a disposable
  project, with no transaction exceptions in its logs; shutdown exited zero.
- Final installed archive contains 30 files matching the ZIP, with no extras.
  Review-only upstream source files were quarantined before final packaging;
  the runtime JAR remained byte-identical to the tested JAR.
- FORD restarted with the corrected revision, authenticated to the repository,
  and successfully listed its 14 root entries. No production programs were
  opened or reanalyzed during this repair.

The other agent should reopen its intended program, rediscover its exact ID,
and rerun full analysis for programs affected by the old errors. Old task IDs
do not survive the restart. Inspect the new operation result and save afterward.

Evidence: `build/upgrade-validation/analysis-transaction/`, including
`release.json`, `installed.json`, `packaged-analysis.json`,
`native-analysis.json`, native logs and `ford-verified.json`.

Final ZIP SHA-256:
`8f85b61813cdac0abd7847e32d848601c9dd999ed147d7858e899637bec89056`.

Runtime JAR SHA-256:
`4b6f1b9f3220d8837541833d0a8bd46eb5a1bae4d00bb3a0a6df31b705019275`.
