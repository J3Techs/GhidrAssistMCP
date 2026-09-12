# Lifecycle fixes from the Grok review

Implemented against the working tree reviewed in `build/grok-review-5b3a058.md`. These changes address script timeout, GUI teardown, BSim shutdown retries, and both headless ownership paths. They do not add script execution capabilities or change custom tasks into negotiated MCP Tasks.

## Ownership rule

A cancelled Future, closed HTTP listener, elapsed wait deadline, or interruption request does not establish that its worker stopped. Programs remain retained until the actual callback exits; the headless caller retains its project scope until all workers settle.

- `GhidrAssistMCPBackend` closes admission before shutdown, counts synchronous tool/prompt/resource callbacks, interrupts active callers, and drains them before generic tasks and BSim work. Each selected program gets a request consumer; asynchronous submissions retain their separate task consumer. Prompt handlers use `withProgramRequest`, and resource reads retain the exact URI-selected program.
- `OwnedScriptExecution` supplies a cancellable monitor and timeout to both execution modes. Scripts run off the EDT by default; explicit `run_on_edt=true` remains available. An interrupted or timed-out caller waits for the actual Swing callback to exit. Queued, already-cancelled callbacks skip execution. The script lock, mutation guard, transaction, and program ownership cannot be released while the script remains alive. Cancellation callbacks synchronize with completion so they cannot later interrupt a reused worker thread.

  Async script cancellation propagates `CancellationException` after the runner settles so the generic manager reports `CANCELLED`; synchronous cancellation retains its error report. The additional two `RunScriptCancellationTest` cases cover this classification and ownership timing and are assigned to the final integrated validation run.
- `GhidrAssistMCPManager` detaches closing providers, retargets surviving window context, and clears active plugin/tool references on final closure. Final shutdown runs on a background thread, outside the manager monitor and EDT. The singleton remains in its stopping state until the drain completes, preventing replacement backends from overlapping old work.
- `BsimRuntime` tracks queued and actually running work by backend, retains the program before enqueueing, supplies the real cancellation monitor, and waits for actual worker exit. Queue cancellation releases its reservation exactly once. A backend closes only its own work while other owners remain; the final owner closes runtime admission atomically. A failed close remains retryable and retains ownership. Existing job cancellation/error journaling remains in place.
- Both `HeadlessProjectBackend` and the no-project `HeadlessBackend` use the same worker drain before releasing program consumers. Stopping is distinct from listener-running state; rebinding/restarting a stopping backend is rejected. The launcher retries draining instead of unwinding into caller-owned project closure while work remains.

## Launcher compatibility change

`GAMCPStartServerScript` now waits by default and rejects `wait=false` before startup. Use it as an `analyzeHeadless` post-script. Returning from a nonwaiting script did not own the remaining project lifetime and allowed later pipeline closure to race MCP work. Programmatic server start remains nonblocking for callers that own and manage the surrounding project scope themselves. The launcher also drains partial startup failures before returning. README, HEADLESS and REVIEW_VALIDATION document this change.

## Focused verification

The final coordinated focused run passed 19 tests against `C:\GHIDRA\FRESH_GHIDRA` with JDK 25:

| Test class | Cases | Relevant evidence |
|---|---:|---|
| `OwnedScriptExecutionTest` | 5 | Deadline reaches monitor; uncooperative runner retains caller; cancelled queued dispatch skips execution; real Swing interruption preserves ownership and caller interrupt; setup failure settles; cancellation callback cannot outlive owner. |
| `LifecycleShutdownTest` | 4 | Synchronous program consumer stays held; prompt/resource callbacks join shutdown; final GUI drain leaves EDT and manager monitor available; no-project backend drains actual BSim work before consumer release. |
| `BsimRuntimeOwnershipTest` | 2 | Failed close retains consumers and succeeds on retry; cancelling a queued backend releases its reservation while another owner continues. |
| `HeadlessLauncherLifetimeTest` | 2 | Default/explicit wait accepted; false and malformed wait rejected. |
| `AppliedProtocolConformanceTest` | 4 | HTTP resource selection/errors, input/output contracts, and correlated progress still pass with request leases. |
| `ResourceTargetSelectionTest` | 2 | Exact resource program selection survives consumer leasing. |

The preceding run also passed the parent-owned diagnostic purity, temporary analysis options, prototype, BSim authentication and BSim context tests. Its sole failure was a resource test proxy missing ownership methods; the proxy was updated and both resource suites passed above. Tests use temporary state and deterministic latches; they do not run user scripts, touch live projects, or contact remote databases.

## Limits and corrected review claims

Cancellation is cooperative. A script or native operation that never returns can keep its manager/project in stopping state indefinitely; this is intentional ownership preservation, not a forced release. GUI shutdown does not block the EDT. Direct headless stop reports an incomplete drain and supports retry; the launcher retains its project scope and retries. Process termination cannot provide the same in-process ownership guarantee.

The original BSim runtime was not necessarily stuck until JVM exit: a subsequent close could succeed after the worker exited, and running jobs already persisted terminal states. This fix makes retry/admission/ownership explicit and isolates backend owners. Completed generic tasks already released their consumers; the GUI defect was failing to drain active workers and retire the manager safely.

Listener stop does not imply every callback has exited. Resource, prompt, synchronous tool, generic task, and BSim execution are therefore tracked separately from transport state. Custom generic task records remain in memory; the BSim journal remains separate.
