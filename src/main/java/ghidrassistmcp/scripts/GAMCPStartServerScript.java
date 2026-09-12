package ghidrassistmcp.scripts;

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPHeadlessServer;

/**
 * Headless GhidraScript that starts the GhidrAssistMCP server.
 * Designed to be run as a -preScript before GhidrAssistHL scripts so that
 * the MCP server is available for tool calls during ReAct analysis.
 *
 * Usage in analyzeHeadless:
 *   -preScript GAMCPStartServerScript.java
 *   -postScript GAHLQueryScript.java ...
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
        boolean waitForClients = false;
        String completionFile = null;
        String toolProfile = "default";

        // Parse optional arguments: host=... port=... wait=true|false
        String[] args = getScriptArgs();
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
                } else if (arg.startsWith("wait=")) {
                    waitForClients = Boolean.parseBoolean(arg.substring(5));
                } else if (arg.startsWith("completion_file=")) {
                    completionFile = arg.substring("completion_file=".length()).trim();
                } else if (arg.startsWith("tool_profile=")) {
                    toolProfile = arg.substring("tool_profile=".length()).trim();
                }
            }
        }

        GhidrAssistMCPHeadlessServer mcpServer = GhidrAssistMCPHeadlessServer.getInstance();

        if (mcpServer.isRunning()) {
            Msg.info(this, "MCP server already running, updating program reference");
            mcpServer.start(currentProgram, state.getProject(), host, port, toolProfile);
            if (waitForClients) {
                // Release GhidraScript.start()'s transaction before blocking so
                // MCP saves, repository locks, and VT work can proceed.
                end(true);
                waitUntilCancelled(mcpServer, completionFile);
            }
            return;
        }

        Msg.info(this, "Starting headless MCP server for project: " + state.getProject().getProjectLocator());
        mcpServer.start(currentProgram, state.getProject(), host, port, toolProfile);
        Msg.info(this, "Headless MCP server ready on " + host + ":" + port);
        if (waitForClients) {
                // Do not hold the script transaction while the MCP server waits.
                end(true);
                waitUntilCancelled(mcpServer, completionFile);
        }
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
        } finally {
            mcpServer.stop();
        }
    }
}
