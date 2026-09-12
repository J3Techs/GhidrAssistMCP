---
name: ghidrassistmcp-grok
description: Route Grok workflows through GhidrAssistMCP using compact discovery, advertised schemas and bounded result recovery.
---

Read [references/operating-guide.md](references/operating-guide.md). Use the installed client's `search_tool` then `use_tool` flow and discover actual tool arguments from schemas; do not copy a fixed allowlist. Start with compact capabilities and exact `program_id` discovery. Matchers and transfer workflows may still be under implementation, so consult current schemas and report unavailable contracts clearly.

The example config uses documented `[mcp] max_output_bytes = 131072` and `[mcp_servers.ghidrassist]` entries. Grok 1.0.30's local reference confirms both keys and permits the cap in project configuration. Do not create an active project config or change global settings. Spill-file recovery and incomplete JSON handling are client-specific and must be tested before relying on them. Do not reduce tool timeouts by inference.
