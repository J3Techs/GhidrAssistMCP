# Codex integration

Use the Streamable HTTP `/mcp` endpoint. The optional [configuration example](../codex-integration/config.example.toml) includes a focused tool catalog and explicit client timeouts. Merge its settings into the desired user or project Codex configuration; copying the example alone does not register a server. Adjust the URL to the actual listener. The legacy `/sse` endpoint remains for existing clients.

```powershell
codex mcp add ghidra --url http://127.0.0.1:8080/mcp
```

Codex supports startup/tool timeouts, enabled/disabled tool lists, and per-tool output budgets. These settings control the client, not native Ghidra execution. The example's 75-second call timeout leaves room for `wait_task`'s maximum 30-second wait. See [official MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

The checked-in [.agents skill](../.agents/skills/ghidrassist-mcp/SKILL.md) is discoverable when Codex works in this repository. For use from another analysis workspace, copy that skill directory into the workspace's `.agents/skills` or the user's Codex skills directory. No global configuration or skill installation is performed by building this repository. See [official skill documentation](https://developers.openai.com/codex/skills).

## Connect and inspect

Start with `runtime_capabilities`. It exposes the installed build, tool counts, supported protocol revisions, GUI/headless services, open program identities, async setting and task recovery limits. It shares its data with `ghidra://runtime/capabilities`; neither route probes remote repositories or BSim health.

Use exact `program_id` selectors for work spanning multiple calls. Resource discovery now separates six program URI templates from the concrete capabilities resource. Percent-encode the selected program name, exact project path, or program ID when inserting it into `ghidra://program/{name}/...`. Missing and ambiguous targets fail instead of silently selecting the active window.

## Results and long operations

Twelve tools publish concrete output schemas: two searches, the six batch/inventory tools, runtime capabilities, and three task controls. The [catalog audit](TOOL_CATALOG_AUDIT.md) lists each contract. Completed results are checked before caching or successful task completion, and async descriptors accept both completion and submission shapes. Server responses retain standalone JSON text fallback for text-only clients. Other tools retain their established formats; there is no universal response envelope or global result-size bound.

Async submissions include structured task metadata. `wait_task` returns lifecycle metadata without repeating the potentially large operation payload. Omit `after_version` to wait for terminal completion, or use the last `state_version` to wait for a change. A `timeout` outcome does not cancel work. Fetch the retained result with `get_task_status` after the task settles. `list_tasks` now pages full IDs and structured state records.

When the client supplies `_meta.progressToken`, `wait_task` sends increasing progress observations through that request's exchange. Progress measures elapsed waiting rather than assuming worker percentages advance monotonically. Without a token no notifications are sent. The wait loop uses one deadline, but a stalled synchronous SDK notification send can exceed the requested wall-clock wait budget. Task-control failures include stable `error.code`, `error.message`, and `error.retryable` fields.

Generic task history is process-local. `manager_instance_id` identifies its lifetime; reconnecting to a restarted manager cannot recover old generic task records. BSim's durable journal remains separate. The task API is an application compatibility interface, not an advertisement of the standardized Tasks extension.

## Supported standards and updates

The server uses MCP Java SDK 2.0.1, Jackson 2.21.1 BOM and Jetty 12.1.13 with Servlet 6. The SDK negotiates through MCP `2025-11-25`; its current stable release does not implement the `2026-07-28` stateless protocol core. The [standards audit](MCP_STANDARDS_AUDIT.md) distinguishes implemented features, compatibility behavior and deferred extensions.

Accept-header rewriting is off by default. For a known legacy client that needs it, start Ghidra with `-Dghidrassistmcp.transport.lenientAccept=true`. This compatibility switch does not restore cross-session identity fallback. Requests with an Origin header must match the configured listener authority; intentional reverse proxies require a separately reviewed origin configuration.

The build stages resolved external dependencies in `build/dependency-libs` and excludes the old generated `lib` directory from compilation and packaging. This prevents mixed SDK or Jackson versions after upgrades. Building the extension does not install it into, or restart, a live Ghidra instance.
