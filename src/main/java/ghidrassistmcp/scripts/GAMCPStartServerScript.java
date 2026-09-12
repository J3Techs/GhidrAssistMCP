package ghidrassistmcp.scripts;

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPHeadlessServer;

/**
 * Headless GhidraScript that starts the GhidrAssistMCP server.
 * Run as a post-script to retain the caller-owned project for the complete MCP session.
 *
 * Usage in analyzeHeadless:
 *   -postScript GAMCPStartServerScript.java wait=true
 */
public class GAMCPStartServerScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (state.getProject() == null) {
            Msg.warn(this, "GAMCPStartServerScript: No project loaded, skipping MCP server start");
            return;
        }

        String host = "localhost";
        int port = 8080;
        String completionFile = null;
        String toolProfile = "default";

        // Parse optional arguments: host=... port=... wait=true|false
        String[] args = getScriptArgs();
        validateWaitMode(args);
        if (args != null) {
            for (String arg : args) {
                if (arg.startsWith("host=")) {
                    host = arg.substring(5);
                } else if (arg.startsWith("port=")) {
                    try {
                        port = Integer.parseInt(arg.substring(5));
                    } catch (NumberFormatException e) {
                        Msg.warn(this, "Invalid port argument, using default 8080");
                    }
                } else if (arg.startsWith("completion_file=")) {
                    completionFile = arg.substring("completion_file=".length()).trim();
                } else if (arg.startsWith("tool_profile=")) {
                    toolProfile = arg.substring("tool_profile=".length()).trim();
                }
            }
        }

        GhidrAssistMCPHeadlessServer mcpServer = GhidrAssistMCPHeadlessServer.getInstance();

        boolean ownedSession = !mcpServer.isRunning();
        try {
            Msg.info(this, "Starting headless MCP server for project: " + state.getProject().getProjectLocator());
            mcpServer.start(currentProgram, state.getProject(), host, port, toolProfile);
            ownedSession = true;
            Msg.info(this, "Headless MCP server ready on " + host + ":" + port);
            // Release the launcher's transaction while keeping its project ownership scope alive.
            end(true);
            waitUntilCancelled(mcpServer, completionFile);
        } finally {
            // Also covers partial startup and transaction-release failures.
            if (ownedSession) mcpServer.stopAndAwaitWorkers();
        }
    }

    static void validateWaitMode(String[] args) {
        if (args == null) return;
        for (String arg : args) if (arg.startsWith("wait=") && !arg.equalsIgnoreCase("wait=true"))
            throw new IllegalArgumentException("The headless launcher requires wait=true (the default) to retain its caller-owned project until all MCP workers stop");
    }

    private void waitUntilCancelled(GhidrAssistMCPHeadlessServer mcpServer, String completionFile) {
        Msg.info(this, "Headless MCP server wait mode enabled; cancel the script or terminate analyzeHeadless to stop");
        try {
            while (!monitor.isCancelled() && mcpServer.isRunning()) {
                if (completionFile != null && !completionFile.isBlank() && Files.isRegularFile(Path.of(completionFile))) {
                    Msg.info(this, "Headless MCP completion file observed; stopping. Explicitly save modified programs before signaling completion.");
                    break;
                }
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
