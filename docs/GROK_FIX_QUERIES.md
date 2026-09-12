# Query correctness fixes from the Grok review

This applies findings 14, 15, 20 and 21 from `build/grok-review-5b3a058.md` to the current modernization branch. Public tool names and existing readable result formats remain available.

| Finding | Applied behavior | Regression evidence |
|---|---|---|
| 14: unreadable hexdump bytes appeared as zero | `get_hexdump` uses `??` in the hex column and `?` in ASCII, with an explicit unreadable-byte count. Actual zero bytes remain `00`. Requests that cross the address-space boundary fail before reading. `len` must be an exact integer in 1â€“65536. | Disposable ProgramDB initialized zero, uninitialized and unmapped bytes; top-of-space wrap rejection. |
| 15: unbounded legacy query output | `get_code` text has `max_chars` (1024â€“200000; default 200000); disassembly and p-code also honor `max_items` (1â€“10000; default 1000). All text truncation carries a visible marker. `list_functions` streams its requested page without retaining all matched Function objects; `offset` and `limit` use exact checked integer parsing, limit at most 1000. Legacy xrefs use a 1000-reference ceiling per direction and a 200000-character response budget. Both call-graph entry points share one emitted-row budget across directions, recursion and repeated nodes, plus the text budget. Graph depth is0â€“5; `get_call_graph.max_nodes` defaults 1000, maximum 10000. `xrefs.include_calls` uses `limit` as its aggregate graph row budget. | ProgramDB pages; graph branching with low aggregate budgets; fractional/string/negative/overflow arguments; actual disassembled instructions and oversized comments. |
| 20: nested project folders | `open_program(action=list)` resolves each project-path component through the shared folder resolver. Absolute, relative, trailing-separator and backslash forms work; absent folders and invalid project paths return tool errors. | Temporary disposable project containing `/banks/ecu/nested`; missing folder and `..` rejection. |
| 21: inconsistent function lookup | `FunctionLookup.resolve` applies exact entry address, containing address, qualified indexed name and existing thunk-aware matching consistently. Adopted by code, signature, blocks, graph, xrefs, analyze_function and function-byte matching. Plain duplicate-name compatibility still selects the lowest entry address; use qualified names or exact addresses to disambiguate. | Existing indexed-name/thunk tests plus containing address and qualified thunk checks; direct ProgramDB cross-tool namespace/interior-address regression. |

Limits describe emitted results and retained Java response text. Function-byte matching also resolves exact program IDs or unique names, rejects malformed byte counts before allocation (1-65536), and preserves long function sizes until after the count is bounded.

Ghidra may still materialize a whole decompiler result or native caller/callee set before this layer can truncate it. `list_functions` still scans to report an exact match total; arbitrary Java regex execution is unchanged. This change does not claim a hard CPU deadline or regex sandbox. Graph depth cutoffs are requested scope; omitted rows caused by budget exhaustion are explicitly marked. To inspect omitted graph regions, select a narrower direction/depth or another root. Structured `get_code` retains its existing bounded structured contract; `max_chars` controls legacy text.

Validation: JDK25.0.4.1+1 and Ghidra installation `C:/GHIDRA/FRESH_GHIDRA`:

```powershell
$env:JAVA_HOME='C:/Users/JResp/.codex/tmp/ghidrassist-modernization/jdk-25.0.4.1+1'
./gradlew.bat -PGHIDRA_INSTALL_DIR=C:/GHIDRA/FRESH_GHIDRA test --tests ghidrassistmcp.tools.QueryFixProgramDbTest --tests ghidrassistmcp.tools.FunctionLookupTest --tests ghidrassistmcp.decompiler.GetCodeExecutionTest --tests ghidrassistmcp.tools.ProjectManagementIntegrationTest --console=plain
```

The focused run passed 23 tests, including production/test compilation. The subsequently added cross-tool namespace/interior-address test is included in the coordinated final validation. All fixtures are disposable; no live user program was changed.
