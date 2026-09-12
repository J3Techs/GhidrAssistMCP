# FORD headless memory exhaustion and recovery

On 2026-09-12 at 09:10 America/Phoenix, the FORD headless service aborted with
`java.lang.OutOfMemoryError: Java heap space`. Three auto-analysis requests
were active and 22 programs were retained. The standard Windows
`analyzeHeadless.bat` hard-codes `MAXMEM=2G`; this was a separate failure from
the repaired analysis transaction ownership issue.

The shutdown log explicitly reported unsaved changes for these project paths:

- `/NewFolder/CUMMINS_INLINE/Cummins_USBLink3_3.3.0.2/x86/tools/CommCheck.exe`
- `/NewFolder/CUMMINS_INLINE/NEXIQ_USBLink2_2.8.2.0/x86/tools/CommCheck.exe`
- `/NewFolder/CUMMINS_INLINE/Cummins_USBLink3_3.3.0.2/x64/tools/dmux64test.exe`

Shutdown released these programs without saving. Task completion messages
during shutdown are not proof of persisted analysis. Recover from each last
saved program, inspect its state, then rerun the intended full analysis.

## Applied recovery

The existing `GhidrAssistMCP-FORD` scheduled task now launches through Ghidra's
documented `support/launch.bat`, with `MaxHeap=8G` and `MaxCpu=2` in the
service's `config.json`. The host had approximately 64 GB RAM and 28 GB free
when sized. No global Ghidra launcher was edited. Authentication continues to
use the existing encrypted credential and native stdin input.

The actual new JVM's `VM.flags` confirmed `MaxHeapSize=8589934592`.
MCP verified headless mode, runtime revision `7368266`, the FORD project and
its 14 root entries. No production analysis was rerun during recovery.
The launcher now records `status=failed` on future failures instead of leaving
its state marked as starting.

## Agent recovery procedure

Use the existing `http://localhost:8080/mcp` service. Open only one of the
affected paths, rediscover its exact `program_id`, inspect saved state, then
submit `analyze_program(mode="full")` if that remains the intended operation.
Wait for its terminal result and inspect `operation_result.isError`. Save
successfully and close that program before proceeding to the next.
Old task IDs expired with the previous JVM. `MaxCpu=2` limits native analysis
workers; it does not serialize separate MCP analysis requests.

Prior failure logs remain under
`C:/Users/JResp/Scripts/GhidrAssistMCP-FORD/state/runs/20260912-073533-113404/`.
Nonsecret launcher/config backups and verification are in
`build/ford-memory-recovery/`. Machine-specific service files remain outside Git.
