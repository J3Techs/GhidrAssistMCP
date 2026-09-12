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

        // analyzeHeadless can pass either key=value or separate key value tokens.
        ParsedArgs parsed = parseArguments(getScriptArgs());
        host = parsed.host;
        port = parsed.port;
        completionFile = parsed.completionFile;
        toolProfile = parsed.toolProfile;

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
        parseArguments(args);
    }

    static ParsedArgs parseArguments(String[] args) {
        ParsedArgs result = new ParsedArgs();
        if (args == null) return result;
        for (int i = 0; i < args.length; i++) {
            String token = args[i];
            if (token == null || token.isBlank()) continue;
            int equals = token.indexOf('=');
            String key = equals < 0 ? token : token.substring(0, equals);
            String value = equals < 0 ? null : token.substring(equals + 1);
            if (isKnownKey(key) && value == null) {
                if (++i >= args.length || args[i] == null || args[i].isBlank() || isKnownKey(args[i]))
                    throw missingValue(key);
                value = args[i];
            }
            if (!isKnownKey(key)) continue; // preserve compatibility with launcher options we do not own
            apply(result, key, value);
        }
        return result;
    }

    private static boolean isKnownKey(String key) {
        return "host".equals(key) || "port".equals(key) || "wait".equals(key)
            || "completion_file".equals(key) || "tool_profile".equals(key);
    }

    private static IllegalArgumentException missingValue(String key) {
        return new IllegalArgumentException("Missing value for headless launcher option '" + key + "'; use " + key + "=value or '" + key + " value'");
    }

    private static void apply(ParsedArgs result, String key, String value) {
        if (value == null || value.isBlank()) throw missingValue(key);
        switch (key) {
            case "host" -> result.host = value;
            case "port" -> {
                try {
                    result.port = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid port value '" + value + "'; expected 1-65535", e);
                }
                if (result.port < 1 || result.port > 65535)
                    throw new IllegalArgumentException("Invalid port value '" + value + "'; expected 1-65535");
            }
            case "wait" -> {
                if (!"true".equalsIgnoreCase(value))
                    throw new IllegalArgumentException("The headless launcher requires wait=true (the default) to retain its caller-owned project until all MCP workers stop");
            }
            case "completion_file" -> result.completionFile = value.trim();
            case "tool_profile" -> result.toolProfile = value.trim();
            default -> { }
        }
    }

    static final class ParsedArgs {
        String host = "localhost";
        int port = 8080;
        String completionFile;
        String toolProfile = "default";
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
