# Review and validation — 2026-09-11

This revision combines the Luna implementation tracks and fixes from two Astra review passes. It retains all 49 official upstream endpoints and all existing custom/BSim names, with 143 registered names in total. A fresh upstream fetch confirmed `upstream/master` at `0d412d1fe3203e98a32f7dc70df21dc8f6f57131` is an ancestor of this branch.

## Implemented

- Ten native VT tools: session lifecycle, correlator discovery/options/ranges, match review, manual function/data associations, native address mapping, and selected preview/apply/unapply. Program and session saves are reported separately.
- Six native analysis tools: GDT catalog, staged C/header parsing, reviewed selected type imports, aligned ProgramDiff, FID catalog and actual FID matching.
- Persistent headless multi-program project access; task consumer ownership, historical-version separation and failed-startup cleanup.
- Exact program targeting, batch save results, repository batch status, project deletion preflight/partial outcomes, and explicit GUI handoff for repository merge conflicts.
- Structured decompilation/pcode/tokens, bounded disassembly, xref filters and structured external imports.
- Runtime capability/build diagnostics and truthful cancellation/error outcomes. MCP mutations, including BSim handlers, are coordinated; generic and BSim jobs retain their distinct lifecycle models.

## Executed validation

`test buildExtension` passed against `C:/GHIDRA/FRESH_GHIDRA` (Ghidra 12.0.2) using JDK 25.0.4.1. Result: **127 tests, 125 passed, 2 skipped, 0 failures**. The skipped checks require live PostgreSQL/Elasticsearch backends.

Tests include:

- All upstream/custom tool registrations and alias compatibility.
- Native VT function-name apply and unapply surviving complete program/project close and disk reopen; accepted-match persistence, stale previews and duplicate manual-pair rejection.
- Native FID database creation, ingestion, explicit database save and positive candidate lookup. The fixture refreshes Ghidra's cached FID language metadata after creating a library.
- Actual header parsing and type import, stale token rejection, archive-linked type conflicts after local renaming, and exact-range ProgramDiff.
- Headless tool execution without a PluginTool, repeated-open consumer deduplication, async target lifetime, verified program persistence and failed server-bind cleanup.
- Structured decompilation, xref/import queries, project workflows and task cancellation/error retention.

## Remaining environment limits

No production Ghidra project, shared repository, installed third-party FID collection or remote BSim database was changed by validation. Live shared-repository checkout/check-in/merge and remote PostgreSQL/Elasticsearch remain environment-dependent. FrontEnd metadata save is explicitly unverified because the native API exposes no durable success signal.

Headless operation holds databases open across requests with `wait=true`; the compatibility default is `wait=false`. Explicitly save before shutdown. Generic task history is not durable; BSim jobs have their own journal. Native UI edits/analysis should be idle during VT/type transactions. Header input limits exclude transitive include expansion and native parser memory. See [HEADLESS.md](HEADLESS.md), [VT.md](VT.md), [NATIVE_ANALYSIS.md](NATIVE_ANALYSIS.md) and [WORKFLOWS.md](WORKFLOWS.md).

The built extension is packaged for installation; building and synchronizing this repository does not replace a plugin already loaded in a running Ghidra JVM.
