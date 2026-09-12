# MCP validation harness

`validation/mcp_conformance.py` is a read-only, rerunnable standard-library Python probe for a running MCP HTTP endpoint. It records each request and response size, elapsed time, parsed JSON/SSE result, and pass/fail state in a machine-readable report.

Run it against the default local endpoint with:

```text
python validation/mcp_conformance.py --endpoint http://127.0.0.1:8080/mcp --output build/upgrade-validation/latest/conformance.json
```

Use `--endpoint URL` for another endpoint. The handshake sends `initialize`, retains the returned `Mcp-Session-Id`, then calls `tools/list`, compact `runtime_capabilities`, and a bounded first `list_binaries` page. If the catalog advertises it, a bounded function search call is also exercised. Both JSON and `text/event-stream` responses are parsed.

`--fixture-ready PATH` optionally records a disposable fixture manifest. The path must resolve under `build/` or `build/upgrade-validation/`; no fixture is created, opened, mutated, saved, or deleted by this harness. Mutation, deep-function, and save/reopen checks belong in a separately authorized fixture run.

The report labels itself with `source: validation/mcp_conformance.py`, includes the endpoint and fixture presence, and stores encoded HTTP byte counts. A nonzero exit code means a required probe failed or the endpoint could not be reached.

For artifact validation, build `check buildExtension writeUpgradeFixtureArgs`, then use `prepare_packaged_fixture.py --archive ZIP --output-dir build/FRESH_DIRECTORY`. It creates a Java argument file using the archive's runtime and dependency JARs plus Ghidra libraries and the test fixture launcher. Launch the argument file with a fresh fixture directory; its `ready.json` records endpoint, code-source JAR and build fingerprint. Create `stop` in that fixture directory for orderly owned-server/project shutdown; `stopped` confirms cleanup. These scripts never install or restart the user's GUI extension.

`benchmark_reads.py --fixture-ready PATH --output REPORT` makes one first-observed, seven warm and one bounded structured decompiler request. It requires actual completed C output and follows a returned task with result-bearing wait. First-observed latency is not automatically a cold-start claim.

`release_evidence.py --archive ZIP --output REPORT` records source, runtime/dependency JAR and archive hashes, Java class version, guide equality, packaging exclusions, and JUnit suite counts. Keep raw client traces in ignored build evidence; publish a concise outcome report without credentials or real program content.
