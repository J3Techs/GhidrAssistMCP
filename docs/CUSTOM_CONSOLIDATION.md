# Custom version consolidation

Consolidated on 2026-09-11 from published `J3Techs/GhidrAssistMCP:custom-tools`
commit `2f60648b2907de9d171fbfc030c0e93582e593ea`.

## Recovered sources

| Source | Disposition |
| --- | --- |
| Current GitHub custom-tools branch | Base: all twelve custom tools, enhanced function matching, server recovery, transport compatibility, and Claude integration. |
| `C:\GHIDRA\GhidrAssistMCP\GhidrAssistMCP` | Recovered uncommitted Manager/Plugin/Provider initialization changes. Its older Server and script runner contain no additional work beyond the published branch. |
| Installed 12.0.2 extension source archive | Confirms the same three local UI changes were shipped. |
| Installed 12.0.3 extension source archive | All Java contents are represented in existing Git history. |
| Documents checkout and Desktop `_RE_Campaigns\_ghidrassist_src` | All Java contents are represented in existing Git history. Root-level duplicate files are not additional sources. |
| Three `AUtomation_IDEAS_OLD` reference/upstream trees | All Java contents are represented in existing Git history; no unique changes recovered. |

Comparison normalizes CRLF/LF before comparing each source file against Java
blobs in the fetched Git history. This avoids treating line-ending changes as
custom implementations. Indexed H: archive paths were not accessible on this
machine during consolidation; their C: archive counterparts were inspected.

Original checkouts and installed extensions were left intact. The task workspace
contains `source-snapshots/inventory.json`, source ZIP snapshots, and binary-safe
Git working-tree patches for provenance and recovery.

## Local UI changes retained

The server manager is registered before constructing the UI provider. Provider
construction occurs during plugin initialization, then the server owner attaches
the provider through `setProvider`. The provider's Window menu group and explicit
visibility setup are retained. This preserves local initialization behavior
without reverting newer transport or custom-tool additions.

The `custom-consolidated` branch records this baseline before upstream migration.
