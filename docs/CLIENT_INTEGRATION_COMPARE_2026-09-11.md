# Claude vs Grok client integration — compare and contrast

Written 2026-09-11. Compares [Claude Code integration ideas](CLAUDE_INTEGRATION_IDEAS_2026-09-11.md) with the [Grok client review](GROK_CLIENT_REVIEW_2026-09-11.md) against the existing [Codex integration](CODEX_INTEGRATION.md). This is a synthesis of those documents, not an approved design and not an implementation.

The two source docs agree on the post-modernization server and on not copying Codex's 27-tool allowlist. They diverge on prompts, hooks, output budgets, and how much Java to touch.

## What each document is

| | [Claude ideas](CLAUDE_INTEGRATION_IDEAS_2026-09-11.md) | [Grok client review](GROK_CLIENT_REVIEW_2026-09-11.md) |
| --- | --- | --- |
| Kind | Brainstorm, not an approved design | Evidence review with a live Grok session |
| Question | How should Claude Code become a first-class client? | Do the new tools need Grok-specific work? |
| Verdict | Yes: plugin plus targeted server contracts (approach B) | Yes: config, skill, docs; little Java |
| Workflow bias | Cross-binary porting first, then deep function, then project | Full new catalog: tasks, BSim jobs, VT, native types, paging |
| Evidence | Claude Code docs checked 2026-09-11; no live Claude session in the doc | Live `ghidra-assist` session, 32 open programs, truncated `runtime_capabilities` |

They describe the same server: 145 registered names, 142 enabled, 12 output schemas, seven stale prompts, Codex already packaged, `claude-code-integration/` still the Bosch 0762 one-off.

## Shared observations

1. **Do not copy the Codex 27-tool allowlist.** Claude defers schemas above a token threshold and gets a tool-search tool. Its `.mcp.json` allowlist is ignored (client bug, issue 20617). Grok only has `disabled_mcp_tools` and discovers tools with `search_tool`. Both keep the full catalog and teach search.

2. **The 0762 function-port skill is stale.** Hard-wired program names, `mcp__ghidra__*` names that do not match the live Claude plugin prefix `mcp__plugin_ghidrassist_ghidrassist__`, and hexdump/`search_bytes` instead of `function_byte_matcher`, `string_anchor_matcher`, and `bulk_transfer_labels`. Claude's existing rename hooks also do not match current tool names.

3. **Skills should teach the new matcher, VT, BSim, and save contracts**, plus exact `program_id`. Display names collide; the active GUI window can change between calls.

4. **No client-only protocol in the JVM.** No per-connecting-client catalog filter (Claude approach C). No MCP Tasks extension. No elicitation. No transplant of Grok ACP/OAuth/named-pipe runtime into Ghidra.

5. **Client-neutral server work both want:** output schemas on the decision tools (`function_byte_matcher`, `string_anchor_matcher`, bulk transfer, VT match listing), paging on large reads, and descriptions that tool-search can hit.

The Claude ideas doc parks a **shared skill core** generated once for Codex and Claude so they do not drift. Grok would be the third consumer of that core. Neither document builds it.

## Conflicts

### Prompts

Claude treats the seven MCP prompts as the natural entry point (`/mcp__<server>__<prompt>`). Approach B rebuilds them around `program_id`, batch tools, and source/target pairs. Today's prompts are static Markdown builders: they take a function name, decompile it, list callers/callees, and append a checklist. None use exact program identity, batch tools, or the task lifecycle.

Grok does not expose prompts. A prompt rewrite does nothing for this Grok client. The skill has to carry the workflow.

If prompts are rebuilt, do it for Claude. Keep the skill as the Grok path.

### Structured output versus text fallback

Claude **does not consume `outputSchema`**. It reads the JSON **text** fallback. Schemas still matter because they make that text stable.

Grok is hurt when text **repeats** `structuredContent`: that duplication burns the 20 KiB budget. The Grok review wants a short digest in the text channel.

Those two asks fight if implemented as two full JSON copies. A compatible shape is: `structuredContent` for clients that use it, and **one** compact JSON text body (not a `[Context]` banner plus a second full copy). Claude still gets parseable JSON; Grok stays under budget. Do not ship a Grok-only prose digest that leaves Claude without JSON.

### Result size

| | Claude Code | Grok TUI |
| --- | --- | --- |
| Default | ~25k **tokens**, then spill | **20,000 bytes**, then spill |
| Override | Per-tool `anthropic/maxResultSizeChars` | Global `[mcp] max_output_bytes` |
| Evidence | Documented constraint | Live `runtime_capabilities` chopped at ~20.5 KiB with 32 programs open |

Grok is the tighter client. Claude's annotation will not help Grok. Raising Grok's byte cap and compacting `runtime_capabilities` help Grok immediately and also help Claude when many programs are open, but Claude's first investment is not that truncation.

### Hooks and safety

Claude **explicitly takes hooks out**: no PreToolUse/PostToolUse, no unattended mode. Safety is Claude permission prompts plus existing server `confirm` / preview-token guards. Elicitation is unsupported.

Grok **puts a mutation hook at P2** because this session is `permission_mode = "always-approve"`. Server guards still exist, but Grok will not prompt.

Same server, opposite client packaging: Claude plugin without hooks; Grok skill or hook because approval is off.

The Grok review's comparison table overstated the current Claude integration ("hooks on `rename_symbol`"). The ideas doc is the correction: those hooks are broken and not the intended direction.

### Resources

Claude: `@` mentions and list/read exist; keep the six program templates plus runtime capabilities; low priority. Subscriptions and list-changed are not advertised and not consumed.

Grok: no resource reader. `ghidra://` URIs in the Codex skill are dead in this client. Use `runtime_capabilities` and `list_binaries` as tools.

### How much server work

Claude's recommended **B** is a plugin **plus** Java: prompt rewrite, schemas on matcher/VT tools, result-size annotations, catalog description pass.

Grok's P0 is **client-side**: project `.grok/config.toml`, a Grok section in the existing skill, and `docs/GROK_INTEGRATION.md`. Java is P1 and only compactness of `runtime_capabilities`.

Claude is willing to change the server for Claude-shaped features (prompts, Anthropic size annotations). Grok is not asking for Grok-shaped Java.

### Skill shape

Claude wants a **real plugin**: `.claude-plugin/plugin.json`, `marketplace.json`, four skills (core operating guide, function porting, deep function work, project operations), and slash-command prompts. Porting is first. Generic triage is excluded.

Grok wants to **extend the existing Codex `.agents` skill** with a Grok section and a family search map. A Grok-adapted port skill is P2, not the center. Catalog completeness and truncation recovery are first.

### Installed Claude package versus intended package

The ideas doc records the current Claude Code install as a single `.mcp.json` plugin (`ghidrassist@custom-plugins`) with no skills, agents, or commands. Repo `claude-code-integration/` is still the 0762 porting kit.

The Grok review treated that kit as "the Claude integration." For packaging decisions, use the ideas doc: the intended Claude surface is a marketplace plugin, not the 0762 folder as it stands.

## What the Grok review got wrong about Claude

The Grok table said Claude prompt/resource support "varies" and treated the 0762 hooks as the Claude package. The ideas doc is sharper:

- Prompts are supported and should be the workflow entry points.
- Resources work via `@`, but are not the investment.
- The installed plugin is only `.mcp.json`; no skills or commands yet.
- Tool prefix is `mcp__plugin_ghidrassist_ghidrassist__`, not `mcp__ghidra__`.
- Structured output is unused by the Claude client; JSON text is what it reads.
- Hooks are out of scope for the intended Claude plugin.

## Three-client matrix

| Capability | Codex (shipped) | Claude Code (ideas B) | Grok TUI (review) |
| --- | --- | --- | --- |
| Transport | Streamable HTTP `/mcp` | Same URL via plugin `.mcp.json` | Same URL as `ghidra-assist` |
| Catalog | 27-tool `enabled_tools` example | Full catalog; tool-search; allowlist ignored | Full catalog; `search_tool`; denylist only |
| Discovery | Tools injected into context | Deferred schemas plus tool-search | `search_tool` then `use_tool`; default 5 hits |
| Output budget | Per-tool token limits (example 24k on `get_code`) | ~25k tokens, then spill; optional Anthropic size annotation | 20,000 **bytes**, then spill |
| Timeout | Example 75s | Claude defaults | Default 6000s; `wait_task` 30s is fine |
| Skill | `.agents/skills/ghidrassist-mcp` | Four plugin skills; core is a Claude-flavored port of the Codex skill | Same Codex skill plus a Grok section |
| Prompts | Documented, not the packaging center | Rebuild as slash-command workflows | Not exposed; ignore |
| Resources | Documented URI templates | Keep; `@` mention; low priority | Not exposed; use tools |
| Hooks | Not part of Codex package | Out | Optional P2 because auto-approve |
| Integration package | `docs/CODEX_INTEGRATION.md`, `codex-integration/config.example.toml` | Intended: real plugin + marketplace | None yet; proposed config + `GROK_INTEGRATION.md` |

## Practical synthesis

Do the **shared server slice** both docs want, in a form that does not pick a winner:

- Compact `runtime_capabilities`: count, active program, name collisions; leave the full inventory to `list_binaries`. Optional `include_programs=false`.
- Output schemas on matcher, transfer, and VT match tools, with a **single** JSON text fallback (not a banner plus a second full copy).
- Description tuning so both tool-search implementations land.
- Do **not** add a per-client catalog filter, Grok-only digest, or Claude-only result envelope.

Then split the client packages:

| Claude (ideas B) | Grok (review P0/P2) |
| --- | --- |
| Plugin + four skills + marketplace | Config byte cap + one skill section + integration doc |
| Rebuild MCP prompts with `program_id` | Ignore prompts; teach `search_tool` family queries |
| No hooks | Optional mutation hook only because auto-approve |
| `anthropic/maxResultSizeChars` on `get_code` and friends | `[mcp] max_output_bytes = 131072` |
| Porting workflow first | Catalog completeness and truncation recovery first |

Suggested Grok config (from the Grok review; not checked in by this document):

```toml
[mcp]
max_output_bytes = 131072

[mcp_servers.ghidra-assist]
url = "http://127.0.0.1:8080/mcp"
enabled = true
tool_timeout_sec = 120
tool_timeouts = { wait_task = 35, get_code = 120, analyze_program = 300 }
```

Do not add `enabled_tools`.

The parked **one generated skill core** is the piece that would stop Codex / Claude / Grok from diverging. Neither source document implements it; both client packages will rot without it.

## Recommended follow-up (not done here)

1. A short **shared-client contract** covering capabilities compactness, matcher/VT schemas, and the single JSON text-fallback rule.
2. Two thin wrappers on that contract: Claude marketplace plugin (ideas B) and Grok config/skill (review P0).
3. Do not merge the Claude ideas doc and the Grok review into one design. Keep client packaging separate; share only the server contract and, later, the generated skill core.

## Related documents

- [Claude Code integration ideas](CLAUDE_INTEGRATION_IDEAS_2026-09-11.md)
- [Grok client review](GROK_CLIENT_REVIEW_2026-09-11.md)
- [Codex integration](CODEX_INTEGRATION.md)
- [Codex review](CODEX_REVIEW_2026-09-11.md)
- [Modernization report](MODERNIZATION_2026-09-11.md)
- [Tool catalog audit](TOOL_CATALOG_AUDIT.md)
- [Deployment policy](DEPLOYMENT_TRUST.md)
