# Persistent headless MCP service

CodeBrowser is not required for core analysis or project access. The project backend retains native `Project` and `Program` objects in the same JVM across MCP requests. It supports multiple open programs, exact program identities, project file management, explicit saves, native VT, BSim and local analysis tools.

After installing this extension, start an existing project/program with Ghidra's launcher:

```powershell
& 'C:\GHIDRA\FRESH_GHIDRA\support\analyzeHeadless.bat' `
  'C:\Path\To\Projects' 'MyProject' -process 'existing-program' -noanalysis `
  -postScript GAMCPStartServerScript.java host=127.0.0.1 port=8080 wait=true
```

Replace the project directory/name and program with actual values. Ghidra's ordinary project lock rules apply; another process cannot simultaneously own the same writable project. The launcher backend also accepts a project without a seed program when invoked from a project-bound script context.

The server script accepts both `key=value` and separate `key value` options. Ghidra's Windows batch launcher can split arguments at `=`, so both forms must resolve to the same host, port, wait mode and completion file. Quote paths containing spaces. Invalid ports and missing option values fail before server startup.

`wait=true` keeps the script/server/JVM alive until cancellation, server stop, or an optional `completion_file` signal. Waiting is now the default; `wait=false` is rejected because returning to the headless pipeline can close the caller-owned project while MCP work still runs. Use the launcher as a post-script. Programmatic server callers may still start it without blocking when they explicitly own the surrounding project lifetime. The script ends its own program transaction before waiting, permitting subsequent MCP saves and VT transactions.

`open_program` retains a consumer until `close_program` or shutdown. Repeated opens reuse the same requested version; historical versions and the current checkout stay distinct. Async tasks hold an additional consumer so closing an MCP program handle does not invalidate work already queued or running. The caller owns the project itself; backend shutdown does not close it.

**Save before shutdown.** Edits live in memory until `save_program` succeeds; VT additionally requires `vt_session(action=save)`. Stopping the server or supplying a completion file does not save every database. Unsaved objects are reported in the shutdown log. `analyzeHeadless` may subsequently save its own processed seed program, but this does not save additional MCP-opened programs. `ignore_changes=true` releases an MCP handle; it cannot discard edits still retained by another consumer.

Headless `analyze_program` owns a database transaction through native analysis and its completion cleanup, including analyzer timing writes. Both `full` and `changes` modes use this lifecycle; `open_program(analyze_after_open=true)` uses the same analysis tool. As in Ghidra's native headless runner, completed analysis work remains in memory after cancellation or failure, and temporary per-call options are restored after analysis stops. Inspect the result and use `save_program` to persist the desired state.

Shutdown drains generic tasks and BSim work before releasing project-scoped VT sessions and program consumers. It reports failure instead of claiming completion if workers do not stop. Generic task records are memory-only and are lost on JVM restart; BSim has a separate persistent job journal.

GUI cursor tools and `save_project_session` are disabled in the project backend. Interactive repository conflict resolution still uses Ghidra's merge UI. Repository credentials and remote BSim database availability remain prerequisites independent of CodeBrowser. The default security settings for host imports, script execution and exports are preserved.

Read `ghidra://runtime/capabilities` for the actual backend, project, open program IDs, enabled tools, native correlators, build revision and dirty-build marker. The resource does not probe remote services.

Validation exercises tool calls without a PluginTool, multiple opens, exact consumer ownership during async work, failed server-bind rollback, and save/close/reopen persistence. No installed production project or remote database is used by these tests.
