# Generic task lifecycle and cache audit

Reviewed and implemented September 11, 2026. These APIs are the existing
GhidrAssistMCP custom async tool lifecycle, **not** a claim of negotiated MCP Tasks
extension support. BSim jobs retain their separate lifecycle and journal.

## Implemented contract

Long-running tool submissions retain their existing text acknowledgement and add
structured lifecycle metadata. Each task has a UUID, a monotonically increasing
`state_version`, captured program identity including project/version, and a
`manager_instance_id` identifying the in-memory manager. Nested JSON arguments
are frozen before asynchronous execution so queued work observes its submitted
inputs. Snapshot reads are atomic with respect to progress and terminal changes.

`wait_task` accepts:

| Argument | Behavior |
| --- | --- |
| `task_id` | Required existing task UUID. |
| `timeout_ms` | Integer from 0 through 30000, default 25000. Zero returns immediately. |
| `after_version` | Optional previously observed version for this same task. Return on a newer version or terminal state. Omit to wait for terminal state. |

The response contains `schema_version: 1`, the task and manager identities,
`state_version`, status/progress/timestamps, program context, `terminal`,
`result_available`, and `wait_outcome` (`terminal`, `changed`, or `timeout`). A
`result_tool` value of `get_task_status` identifies the retained payload reader.
Free-text metadata fields cap at 2048 Java characters and
`metadata_truncated` explicitly reports clipping. Operation results and submitted
arguments are never copied into the wait response. `wait_task` advertises an
output schema through the backend.

```json
{"task_id":"<submitted UUID>","timeout_ms":25000}
```

For progress following, pass the returned `state_version` as `after_version` in
the next call. Versions ahead of the current task version, fractional budgets,
negative values, and oversized budgets fail explicitly. A terminal task returns
immediately even when its version has already been observed.

**The wait deadline belongs to the caller, not to the operation.** Timeout and
interruption of a waiter do not invoke operation cancellation. A timeout returns
the current nonterminal task status; callers can wait again. A failed operation
is a successful status observation with `status: FAILED`; use
`get_task_status` for its original error payload.

`get_task_status` retains its existing terminal operation-payload contract,
including original structured content and `isError`. Missing tasks, invalid
task IDs, and terminal failure/cancellation without a retained payload now use
`isError: true`. A worker returning no result now becomes `FAILED`, preventing a
false completed task with no retrievable result.

`cancel_task` reports a **cancellation request** rather than prematurely claiming
completion. Queued tasks can settle immediately; running workers settle after
they stop. Noncooperative workers can still complete normally and retain their
result. The cancellation control call bypasses the program mutation lock, so a
caller can interrupt a mutating operation that currently holds that lock.
The cancellation handle is published before the task becomes discoverable.

`list_tasks` accepts optional `status`, `offset` (default 0), and `limit` (default
20, maximum 100). It returns bounded task metadata, full task UUIDs, total/returned/
omitted counts, `has_more`, and `next_offset` when applicable. Pages sort by
creation time descending with UUID tie-breaking. The offset view is live;
new submissions between pages can change positions. Existing summary text is
now concise, and filtered lists are bounded rather than dumping every result.

## Cache findings and changes

The previous revision already preserved raw async results, admitted successful
async results into the normal cache, excluded failures/cancellation requests,
and checked program revision plus option discriminators before/after execution.
Context decoration happens when returning a cached result, avoiding stale
active-window headers. Canonical cache keys include exact program identity;
queries do not share a lossy 32-bit argument hash.

This pass adds serialized admission budgets:

- At most 1000 entries and a 5-minute maximum age, retaining existing defaults.
- At most 32 MiB of serialized results plus cache-key UTF-8 bytes in aggregate.
- At most 1 MiB of serialized result/key bytes for one entry.
- Serialized admission/eviction and replacement accounting, so concurrent
  workers cannot exceed the entry or byte budgets.
- Rejection and serialized-byte counters in cache statistics. Oversized or
  unserializable results are returned normally to their caller but not cached.

Byte budgets are serialized-size admission estimates, not exact heap limits.
Structured objects, strings, and bookkeeping have JVM overhead, and measuring a
result temporarily allocates its serialized representation. Task-retained
results are independent of this cache and do not inherit these budgets.

## Validation

### Applied structured contracts and request progress

`wait_task`, `list_tasks`, and `cancel_task` now publish concrete output schemas,
including bounded nested task metadata and explicit success/error alternatives.
Errors carry `schema_version: 1` and
`error: { code, message, retryable }`; codes distinguish invalid arguments,
missing tasks, unavailable backends, interrupted waits, and cancellation requests
that cannot be accepted. Cancellation success includes the captured task state
and `cancellation_requested: true`. Listing schemas require `next_offset` only
when more results exist. Schema tests validate real tool responses, rather than
checking only that a declaration exists.

Legacy summary text remains the first content block. A second text block contains
the serialized structured object for clients that do not consume
`structuredContent`. This follows the compatibility recommendation in the
[2025-11-25 tool result specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content).
`get_task_status` still returns the original terminal operation payload and does
not wrap it in the new task-control schema.

When a `tools/call` request for `wait_task` supplies a valid `_meta.progressToken`,
the server now sends actual `notifications/progress` through that request's
exchange. Notifications measure **elapsed wait seconds**, with the caller's wait
budget as `total`; the human-readable message includes observed worker state.
They do not reuse potentially resetting task percentages as protocol progress.
Intermediate notifications are limited to approximately four per second plus a
final observation. Every wait uses one monotonic deadline, including when worker
versions keep changing. Without a token, the existing efficient blocking wait
remains in use. Progress scope is not inherited by asynchronous task workers.

The deadline bounds the local wait loop, not all HTTP I/O. The SDK's synchronous
progress send can block on a slow transport and exceed the absolute wall-clock
budget; final result serialization/transport also falls outside that wait-loop
bound. Optional progress failures disable further notifications without
cancelling the operation. This is not an end-to-end HTTP deadline guarantee.

The [2025-11-25 progress specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress)
requires the originating active request's string/integer token, increasing
progress values, and notifications that stop when that request completes. This
implementation reports only while the custom wait request remains active; it
does not claim the token lifetime extension belonging to negotiated MCP Tasks.

Request progress is distinct from MCP logging. The
[2026-07-28 logging specification](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging)
deprecates adopting protocol log notifications for new implementations and points
to stderr/observability alternatives. Task progress therefore uses
`notifications/progress`, not `notifications/message` or a new logging capability.

`TaskToolSchemaContractTest` covers success/error schema validation, JSON text
fallback equality, invalid continuation contracts, monotonic progress, deadline
preservation under worker updates, version-follow completion, waiter interruption,
and unchanged legacy terminal results. The HTTP standards suite separately
exercises request tokens over the actual transport.

Focused Gradle suites run against Ghidra 12.0.2 at
`C:/GHIDRA/FRESH_GHIDRA`, Temurin JDK 25.0.4.1, and the updated MCP SDK 2.0.1:

- `TaskWaitLifecycleTest`: timeout vs cancellation, version wakeup, interrupted
  waiters, strict parameter validation, output-schema advertisement, null/error
  outcomes, cancellation during a guarded mutation, version-specific program
  identity, bounded listing, clipped metadata, and immutable worker arguments.
- `CacheAdmissionTest`: oversized admission rejection, replacement and clear/
  invalidation accounting, concurrent byte/entry bounds, and invalid capacities.
- Existing `CacheExecutionTest`, `AsyncTaskContextTest`, and
  `McpTaskManagerWorkflowTest` preserve async cache/context behavior and the
  original cancellation/error-result contracts.

All focused suites passed. Validation used local fixtures and test backends;
no live user project or BSim backend was modified.

## Remaining lifecycle limits

1. Generic history is in memory. Restart loses both IDs and retained results;
   manager identity makes that scope explicit but does not provide recovery.
2. Retention cleanup runs when new tasks are submitted. The nominal one-hour
   terminal retention is not a timer-enforced expiry. There is no completed-task
   count/byte cap, result pagination/artifact store, or durable journal.
3. The fixed worker pool still has an unbounded submission queue. Admission
   quotas and a byte budget for task-retained results need a separate design
   covering overload responses, ownership, and in-flight result retrieval.
4. Cancellation is cooperative and cannot guarantee interruption of native or
   noncooperative work. Shutdown can fail if workers do not stop, retaining
   program consumers to avoid use-after-close.
5. Wait versions are per-task observations, not replayable event streams. The
   wire tools do not negotiate MCP Tasks, publish native task notifications,
   or establish a cross-session durable task owner.
6. Cache TTL uses wall time and eviction uses creation age, not LRU. There is no
   single-flight deduplication; simultaneous equivalent misses can still run
   twice. Byte admission does not bound the memory needed to compute a result.

Follow-on priorities are bounded submission/result storage and explicit task
ownership first, then negotiated protocol task support once the selected SDK
and clients support the chosen extension contract. Preserve these custom tools
as compatibility adapters if standard task support is introduced.
