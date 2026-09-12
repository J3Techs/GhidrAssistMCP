# Repository connection churn during program selection

The reported FORD `RepositoryAdapter` connect/disconnect bursts are consistent with an unnecessary repository lookup in `ProgramIdentity.matches`. This is a confirmed source-level trigger, not a live stack-trace attribution of every log entry.

## Evidence

- The installed Ghidra 12.0.3 `DomainFileProxy` source implements a local project's `getSharedProjectURL` by reading project properties, obtaining a repository adapter, connecting, validating the file identity, and disconnecting in `finally`.
- `ProgramIdentity.resolve` checks all open programs to detect ambiguous selectors. Previously, `matches` requested the shared URL for each unrelated program even when the selector was a local program ID, project path, or display name. A non-null shared URL was requested twice.
- The installed GhidrAssistMCP source archive contains this same lookup pattern. Its build metadata identifies revision `5b3a058282164c67353b17a49fdb8e226c4eba87`, dirty, built at `2026-09-12T01:25:02.309320300Z`. Installed artifact inspection alone does not establish what an existing JVM has loaded.
- The application log shows the reported bursts around concurrent `xrefs` and `list_binaries` activity. Intentional temporary repository handles can produce these INFO entries; the entries alone do not establish a network outage.

## Change

Only an explicit server URL selector may reach the shared-URL alias lookup after local identity, path, and URL comparisons fail. That lookup now evaluates the shared URL once. Exact identity and ambiguity checks remain intact.

Native remote-project proxies construct their shared URL directly. Their URL getter calls are distinct from the connection-producing local-project-properties path. Explicit shared aliases can still require native repository validation; this patch does not disable that behavior or promise to eliminate every repository connection message.

## Validation and deployment boundary

Four regression tests cover local selectors across 24 programs, missing and stale selectors, duplicate names, local identity/diagnostics, and explicit shared aliases. Mock shared getters fail immediately if a local lookup probes the repository. The focused tests and full suite passed: 373 tests, 371 passed, two external BSim tests skipped, zero failures or errors.

The source fix has not been installed or loaded into the user's running Ghidra instance. No live programs were mutated, closed, or restarted for this diagnosis. Deployment must follow the clean-artifact and state-preservation runbook in the upgrade plan before claiming a live improvement.
