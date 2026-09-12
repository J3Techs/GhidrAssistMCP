# Installed upgrade and native headless validation

The Ghidra 12.0.3 user extension was updated on September 11, 2026. The installed files and a newly launched native headless JVM were verified separately. No production program or shared repository was opened or modified during validation.

## Installed artifact

- Source revision: `62f1e92861c0c70505752daec185bf2d3928555c`; source-scoped `dirty=false`.
- Source SHA-256: `834902eb3ce0b2f4d2931ce723d515fc38d7cad51521ad7d607ef66aa2f8b9d5`.
- Archive: `dist/ghidra_12.0.3_PUBLIC_20260911_GhidrAssistMCP.zip`.
- Archive SHA-256: `4a34f3199c5df71886573c24deb75bc92a48b596b57cb922e32140d738dab649`.
- Runtime JAR SHA-256: `875da64e352caf0d383861f9eab88b52b1b3a0b5b135a8f6dbaf1ce886c6d109`.
- Installed directory: `C:\Users\JResp\AppData\Roaming\ghidra\ghidra_12.0.3_PUBLIC\Extensions\GhidrAssistMCP`.
- Rollback backup: `build/install-backups/20260911-221742`, outside Ghidra's scanned extension directories. This preserves the original extension and distribution-drop archive.

All 30 installed files matched the archive byte for byte; no extra files remained in the extension directory. The distribution-drop ZIP also matched. Installation used `installExtension -x buildExtension` after verifying the archive hash, resolved cleanup targets, original backup and absence of an active JAR lock. The inaccessible residual old Java process was not terminated or claimed to have loaded the update. The user's PyGhidra shortcut targets this same Ghidra distribution.

## Validation

| Check | Result |
| --- | --- |
| Full Gradle `check buildExtension` | Passed: 375 tests, 373 passed, two external BSim tests skipped |
| Build provenance, Java 21 class target, operating-guide equality, packaging exclusions | Passed |
| Installed native `analyzeHeadless.bat` startup | Passed at `127.0.0.1:18080`; loaded source hash/revision matched the installed artifact |
| Runtime separation | `headless=true`, `gui=false`, `headless_session=true`, `program_manager_available=false` |
| Multiple program opens and exact selectors | Passed for source, target and a program named `space # selector` |
| MCP conformance, paging, encoded resource selector and available aliases | Passed |
| Structured decompilation | All four sampled requests completed; first observed 293 ms, two warm requests median 3 ms; not a cold-start benchmark |
| Prototype/name preview and apply, PORT verification, explicit save and consumer reacquisition | Passed on the disposable target |
| Full process shutdown and disk reopen | Passed; verified PORT checkpoint and decompiled `answer_port` survived native JVM restart |
| Completion-file shutdown | Both corrected native test runs exited with code 0 |

Native Windows testing exposed that the batch launcher splits `key=value` options into separate tokens. The first unmodified fixture run therefore ignored its requested port and completion file. That owned test JVM was terminated before any MCP mutations. The script parser was fixed to support both argument forms, regression tests were added, and the extension was rebuilt and reinstalled before the successful runs above.

Raw evidence is retained under `build/upgrade-validation/install-20260911/`: `release.json`, `installed.json`, `headless-fixed/conformance.json`, `headless-fixed/decompile.json`, `headless-fixed/port-workflow.json`, `headless-reopen/verified.json`, and native launcher logs. The earlier `packaged-conformance.json` belongs to the intermediate `9221719` artifact; the final installed native checks above cover `62f1e92`.

## Scope remaining

These results establish installed headless operation and disposable database persistence, not production FORD repository authentication, GUI reload, remote BSim availability, or elimination of every repository connection message. The repository lookup fix is included, but live FORD log behavior was not retested. The separate review backlog remains in `SERVER_NEXT_STEPS_2026-09-11.md`; installation does not mark those follow-on items complete.

The test servers were stopped after validation. Codex's existing `http://localhost:8080/mcp` configuration was not changed and no production headless project was launched. Use `HEADLESS.md` and `INSTALL_RUNBOOK.md` when selecting and launching the production project.
