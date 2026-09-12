# Grok integration

[`grok-integration/config.example.toml`](../grok-integration/config.example.toml) is an inactive fragment using Grok's documented `[mcp_servers.ghidrassist]` HTTP registration and `[mcp] max_output_bytes = 131072` cap. Apply it only after checking the installed client and endpoint.

Keep project configuration inactive until precedence is verified. Use `search_tool` → `use_tool`, canonical family searches, exact program IDs, and live schemas. Matchers and transfer contracts are not claimed available by this package merely because the workflow is documented.

An isolated Grok 1.0.30 headless smoke was attempted with a read-only prompt. The disposable project config was discovered, but Grok marked the temporary folder untrusted and skipped its project-scoped `ghidrassist` server, so the requested tool was unavailable. This trust gate is a client environment gap; it is not evidence that GhidrAssistMCP connectivity works or fails. The rerunnable client smoke script records `grok inspect --json` without modifying global configuration.

Read-only inspection found Grok 1.0.30 (build `04b7ffed98c6`) uses `[mcp_servers.<name>]`; its local documentation says project configuration replaces the user entry and has higher precedence. It also explicitly documents `[mcp] max_output_bytes` and project-file support. The installed config currently exposes a server named `ghidra-assist`, so the requested `ghidrassist` key still needs an isolated registration test. `grok inspect --json` is the available discovery command and reported the configured server without making a connection claim.
