param(
    [string]$PluginDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$McpConfig = "",
    [string]$Endpoint = ""
)

# Read-only client smoke. The server endpoint must already be running.
# This script does not install plugins, edit global settings, or approve MCP servers.
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($McpConfig) -and [string]::IsNullOrWhiteSpace($Endpoint)) { $McpConfig = Join-Path $PluginDirectory ".mcp.json" }
$smokeDir = Join-Path ([IO.Path]::GetTempPath()) ("ghidrassist-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $smokeDir | Out-Null
try {
    Push-Location $smokeDir
    Write-Output ("Claude version: " + (& claude --version 2>&1 | Select-Object -First 1))
    $claudeConfig = $McpConfig
    if (-not [string]::IsNullOrWhiteSpace($Endpoint)) {
        $claudeConfig = Join-Path $smokeDir "mcp.json"
        @{ mcpServers = @{ ghidrassist = @{ type = "http"; url = ($Endpoint.TrimEnd('/') + "/mcp") } } } | ConvertTo-Json -Compress | Set-Content -LiteralPath $claudeConfig -Encoding UTF8
    }
    claude --print --plugin-dir $PluginDirectory --mcp-config $claudeConfig --strict-mcp-config '--allowed-tools=mcp__ghidrassist__runtime_capabilities,mcp__ghidrassist__list_binaries' 'Use only runtime_capabilities and list_binaries from GhidrAssistMCP. Call runtime_capabilities with include_programs=false and list_binaries with limit=1 if those arguments are accepted by their schemas. Do not edit files or call other tools. Report exact tool names, accepted arguments, and structured result fields.'
    Write-Output ("Grok version: " + (& grok --version 2>&1 | Select-Object -First 1))
    Write-Output "Grok inspect (read-only; does not prove MCP connectivity):"
    $inspect = & grok inspect --json 2>$null | ConvertFrom-Json
    [pscustomobject]@{ grokVersion=$inspect.grokVersion; mcpServers=$inspect.mcpServers; skillCount=@($inspect.skills).Count; configSources=$inspect.configSources } | ConvertTo-Json -Depth 6
}
finally {
    Pop-Location
    $resolved = [IO.Path]::GetFullPath($smokeDir)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith("ghidrassist-smoke-", [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    } else { Write-Error "Refusing cleanup outside the verified temporary smoke directory: $resolved" }
}
