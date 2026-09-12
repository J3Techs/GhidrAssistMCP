# GhidrAssistMCP installation runbook (Windows)

This runbook applies a built extension to a Windows Ghidra installation while
keeping a recoverable copy of the previously installed user extension. It is
intended for a local operator with the Ghidra GUI and any headless Ghidra JVM
stopped. A build archive, an installed extension, and an already loaded JVM are
separate artifacts; building the first does not update either of the latter.

## Before touching the installation

Record the source checkout, the intended Ghidra directory, and the operator's
intended project. The supported local toolchain for this checkout is JDK
`C:\Users\JResp\.codex\tmp\ghidrassist-modernization\jdk-25.0.4.1+1` and the
Ghidra distribution is `C:\Users\JResp\Desktop\ghidra_12.0.3_PUBLIC`. Use the
actual paths for the machine being changed; `GHIDRA_INSTALL_DIR` must be an
absolute path to the distribution whose `Ghidra/application.properties` and
profile identify the intended Ghidra installation. Use the Gradle version
specified by that installation's build support.

Verify that Ghidra is stopped before backup or installation. Close all
CodeBrowser and project windows, then check Task Manager or PowerShell for the
Ghidra launcher/JVM. Do not terminate an unrelated Java process merely because
it is named `java.exe`; identify its command line or process owner first. For a
headless server, stop the launcher that owns the project as well. Installation
must not race a JVM that can reload or write the extension.

## Make a dated user-extension backup

The Gradle script installs to the Ghidra user Extensions directory. On Windows
its default is derived from `%APPDATA%\ghidra\<DISTRO_PREFIX>_<RELEASE_NAME>\Extensions`;
the exact versioned directory is supplied by Ghidra's build support. If the
operator uses a custom location, pass the same location through
`GHIDRA_USER_EXTENSIONS_DIR` (or `-PGHIDRA_USER_EXTENSIONS_DIR=...`) when
running Gradle. Never guess a nearby AppData directory.

Resolve and inspect the exact extension directory before copying it:

```powershell
$userExtensions = 'C:\Users\<user>\AppData\Roaming\ghidra\<profile>\Extensions'
$installed = Join-Path $userExtensions 'GhidrAssistMCP'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path (Get-Location) 'build\install-backups'
$backup = Join-Path $backupRoot $stamp
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
Resolve-Path -LiteralPath $userExtensions
if (Test-Path -LiteralPath $installed) {
    Copy-Item -LiteralPath $installed -Destination (Join-Path $backup 'GhidrAssistMCP') -Recurse -Force
    Get-ChildItem -LiteralPath $backup -Recurse -File | Measure-Object
}
```

A backup is valid only when its path and file inventory have been recorded.
Keep it outside the scanned `Extensions` directory (for example,
`build\install-backups\20260911-221742`) so Ghidra cannot discover the backup
as a second extension. Copy the extension directory itself, not all of
`%APPDATA%` and not the whole Ghidra distribution. Also record any matching
extension zip in the distribution drop directory
(`<GHIDRA_INSTALL_DIR>\Extensions\Ghidra`); the install task removes matching
`*_GhidrAssistMCP.zip` files before copying the new archive.

## Build and validate the destructive target

From the repository root, the normal verification command is:

```powershell
$env:JAVA_HOME = 'C:\Users\JResp\.codex\tmp\ghidrassist-modernization\jdk-25.0.4.1+1'
.\gradlew.bat -PGHIDRA_INSTALL_DIR='C:\Users\JResp\Desktop\ghidra_12.0.3_PUBLIC' test buildExtension --console=plain
```

`buildExtension` writes the distributable zip under `dist\`. Check its name,
timestamp, size, and SHA-256 before applying it:

```powershell
Get-ChildItem .\dist -Filter '*_GhidrAssistMCP.zip' |
    Get-FileHash -Algorithm SHA256
```

`installExtension` is a native Gradle task in this repository. It depends on
both `copyExtensionZip` and `extractExtension`: it cleans matching old drop
zips, copies the newly built zip to `<GHIDRA_INSTALL_DIR>\Extensions\Ghidra`,
cleans the user `GhidrAssistMCP` directory, and extracts the archive there.
Therefore validate the target immediately before running it:

```powershell
$ghidra = (Resolve-Path -LiteralPath 'C:\Users\JResp\Desktop\ghidra_12.0.3_PUBLIC').Path
if (-not (Test-Path -LiteralPath (Join-Path $ghidra 'Ghidra\application.properties'))) {
    throw "GHIDRA_INSTALL_DIR is not a Ghidra distribution: $ghidra"
}
if ($ghidra -eq (Resolve-Path -LiteralPath (Get-Location)).Path) {
    throw 'Refusing to use the source checkout as GHIDRA_INSTALL_DIR'
}
```

Confirm that the resolved path is the intended distribution, that the dated
backup exists, and that no Ghidra JVM is running. Then, and only then, run:

```powershell
.\gradlew.bat -PGHIDRA_INSTALL_DIR=$ghidra installExtension -x buildExtension --console=plain
```

The `-x buildExtension` exclusion is deliberate: after the archive has been
validated, do not regenerate it during installation, since generated build
metadata/timestamps can change the bytes being applied. If a Ghidra-related
PID remains visible but has no window, record that it was inaccessible rather
than killing an unrelated JVM; verify the stopped MCP log and that the target
JAR has no active file lock before proceeding.

Use `-PGHIDRA_USER_EXTENSIONS_DIR` or the corresponding environment variable
if the backup was made in a custom user Extensions directory. Do not use
`uninstallExtension` as a cleanup shortcut: it removes the installed extension
and matching copied zips.

## Verify provenance after installation

Compare the generated archive with the installed contents rather than relying
on a filename alone. Hash the archive and each installed jar, inspect the zip
manifest and `extension.properties`, and record the checkout revision and dirty
state alongside the hashes:

```powershell
$archive = Get-ChildItem .\dist -Filter '*_GhidrAssistMCP.zip' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256
Get-ChildItem -LiteralPath $installed -Recurse -Filter '*.jar' |
    Get-FileHash -Algorithm SHA256
git rev-parse HEAD
git status --short
```

The archive is the build artifact, the extracted files are the user install,
and a running Ghidra JVM may still have the previous classes loaded. Restart
Ghidra after a successful install; a hash comparison alone cannot prove what a
running JVM has loaded.

## Rollback

Stop Ghidra and any headless launcher first. Resolve the exact current
`GhidrAssistMCP` directory and move it to a new failure-dated directory under
the external backup root (for example,
`build\install-backups\failed-20260911-221742`). Restore the selected dated
backup into the original path, then inspect its inventory and hashes. Keep the
failed install directory outside `Extensions` until verification is complete.
Do not recursively delete a computed path until it has been resolved and
confirmed to be the intended user extension directory. If the distribution
drop zip was changed, restore the previously recorded matching zip as well.

Restart Ghidra only after the restored files are in place. If rollback itself
fails, leave the preserved directories intact and correct the target path
manually; do not broaden the deletion scope.

## Restart, headless ownership, and runtime checks

For headless use, start the intended project/program with the Ghidra launcher
and post-script, for example:

```powershell
& 'C:\GHIDRA\FRESH_GHIDRA\support\analyzeHeadless.bat' `
  'C:\Path\To\Projects' 'MyProject' -process 'existing-program' -noanalysis `
  -postScript GAMCPStartServerScript.java host=127.0.0.1 port=8080 wait=true
```

The caller owns the project. MCP-opened programs retain consumers until
`close_program` or shutdown, and edits remain in memory until `save_program`
succeeds (VT has its own save operation). Stopping the server or supplying a
completion file does not claim that every live database was saved. Observe the
project's ordinary lock rules and do not start a second owner for the same
writable project.

After restart, query `ghidra://runtime/capabilities` through `/mcp` and verify
the actual Ghidra version, build revision/dirty marker, protocol/runtime
capabilities, enabled tools, project context, and exact open `program_id`s.
Use those IDs for subsequent requests and verify the expected program again
after reopening. The capability resource does not probe remote services and a
successful response does not prove that unsaved live edits were persisted.

Regression validation uses disposable ProgramDB/GhidraProject fixtures and
does not authorize or modify an installed production project or remote
database. Treat the installed jar, loaded JVM, and reopened project as separate
verification steps.
