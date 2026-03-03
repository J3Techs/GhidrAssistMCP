# Claude Code Integration for GhidrAssistMCP

Tools, skills, and hooks for using Claude Code with GhidrAssistMCP to port function annotations between binaries (e.g., from a symbolized ELF to a stripped hex binary).

## Contents

### `skills/ghidra-function-port/SKILL.md`

Claude Code skill that enforces a disciplined pipeline for porting function annotations:

1. **Signature extraction** — Extract prologue bytes from the source binary, wildcard relocatable fields
2. **Byte search** — Find matching functions in the target binary via `search_bytes`
3. **Scoring** — Score candidates by normalized disassembly comparison; CFG tiebreaker for close matches
4. **Full annotation** — Rename function, set prototype, map and rename globals (SDA register offsets + calibration addresses), create structs, type locals, add plate comment
5. **Verification** — Re-decompile to confirm annotations applied correctly
6. **Progress tracking** — Log results to a JSON tracker

**Installation:** Copy to `~/.claude/skills/ghidra-function-port/SKILL.md`

### `hooks/rename-symbol-hooks.json`

Pre/post tool-use hooks that fire on every `rename_symbol` MCP call to enforce the pipeline:
- **PreToolUse** — Reminds to confirm the match was found via signature search with a confidence score
- **PostToolUse** — Checklist of remaining annotation steps after rename

**Installation:** Merge the `hooks` object into your project's `.claude/settings.local.json`

### `scripts/`

Ghidra Java scripts designed for use via the GhidrAssistMCP `run_script` tool:

| Script | Purpose |
|--------|---------|
| `CreateFunctionAt.java` | Create a function boundary at a given address. Useful when Ghidra's auto-analysis misses function starts. |
| `DisassembleAt.java` | Clear and re-disassemble at an address. Fixes Ghidra analysis damage (mis-detected data in code regions). |
| `SetupMPC5676R_MemoryMap.java` | Create SRAM and peripheral register memory blocks for MPC5676R (Freescale/NXP PowerPC). Includes reflection-based exclusive-access bypass for MCP-opened programs. |

**Installation:** Copy to a Ghidra scripts directory registered in your project (e.g., `Ghidra/Features/Base/ghidra_scripts/`).

## Architecture Notes

- **PowerPC VLE** — The skill's byte identification rules are specific to VLE (Variable Length Encoding) used in Bosch EDC17/MED17 ECMs
- **SDA registers** — r13–r17 are Small Data Area base registers. Globals are accessed as signed offsets from these bases. The skill maps globals by positional matching of SDA accesses between source and target
- **Calibration addresses** — `Ke*` prefix constants live in flash calibration segments. Addresses differ between binaries by a consistent offset per region
- **MCP tools** — All Ghidra operations go through GhidrAssistMCP's MCP interface (list_functions, get_hexdump, search_bytes, rename_symbol, set_function_prototype, set_comment, etc.)
