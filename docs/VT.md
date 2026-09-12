# Native Version Tracking

The VT primitives use Ghidra's `VTSessionDB` and native correlator, association, and markup APIs. Sessions retain source and destination file IDs and can be reopened by the project path. Both programs must resolve inside the same project; destination writes are synchronized through the native session object.

The ten registrations are `vt_sessions`, `vt_session`, `vt_correlators`, `vt_correlate`, `vt_matches`, `vt_review_matches`, `vt_add_matches`, `vt_markup`, `vt_apply_markup`, and `vt_unapply_markup`. Match selectors use `match_set_id` plus canonical source and destination addresses. Match listing is bounded with `offset` and `limit` (maximum 500).

Correlation creates one native match set and does not accept or apply markup implicitly. Review status is explicit (`accepted`, `rejected`, or `available`). Applying markup requires an accepted association; unapply uses each native item's `canUnapply`/`unapply` behavior and reports per-item outcomes. Session and destination saves remain separate persistence operations and callers should inspect dirty state after a failure.

`vt_sessions` is read-only (`list` or `get`). Use `vt_session` for `create`, `get`, `save`, and `close`. Creation requires saved, idle source/destination files in the bound project. Sessions are cached by project and file ID, so renames do not create duplicate consumers. Close releases the MCP consumer; other Ghidra consumers can still retain the session or destination and their unsaved changes.

`vt_correlators` describes actual native option values/types and address-restriction support. `vt_correlate` accepts an `options` object and optional paired inclusive `source_range_start/end` and `destination_range_start/end`; default ranges cover memory, including data. Native correlators that prohibit restricted ranges reject those arguments. Cancellation rolls back the current correlation transaction; there is no within-correlator resume mechanism.

`vt_add_matches` validates function entry points or defined-data starts and native object lengths. Duplicate manual pairs are rejected. Manual scores are zero and provenance is explicitly manual, not evidence of native similarity.

For markup, select the match by addresses and optionally `match_set_id`, then call `vt_markup` with any desired native apply `options`. Page its stable string IDs. Repeat those options with selected `markup_ids` and `preview_token` for apply/unapply. Tokens include source and destination revisions, session state, native values and policy. Preview computes address mapping using detached items so stored considered items are not modified during a read.

Unapply can affect multiple native items with the same type and destination address; every `unapply_affected_ids` entry must be selected explicitly. Inspect current/original destination values before undoing. Apply and unapply leave changes unsaved; `vt_session(action=save)` reports independent destination/session persistence outcomes. Native UI edits and auto-analysis should be idle during these transactions. MCP writers are serialized and the source is locked while markup is applied.

Disposable integration tests verify native match review, duplicate rejection, stale tokens, selected function-name apply/unapply, dirty-close refusal, and destination/session persistence after closing all consumers and reopening the project from disk.
