/*
 * RunScriptTool - Execute GhidraScripts programmatically with output capture
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that executes GhidraScripts by name or path.
 * Captures stdout/stderr and returns the output.
 * Supports both Java (.java) and Python (.py) scripts.
 */
public class RunScriptTool implements McpTool {

    @Override
    public String getName() {
        return "run_script";
    }

    @Override
    public String getDescription() {
        return "Execute a GhidraScript by name or path. " +
               "Searches Ghidra script directories if only name is provided. " +
               "Supports Java (.java) and Python (.py) scripts. " +
               "Returns captured stdout and stderr output.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "script_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "script_path", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "script_args", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // This tool needs the backend to access plugin/tool context
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for script execution. " +
                          "Please ensure the MCP server is properly connected.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        // Get parameters
        String scriptName = (String) arguments.get("script_name");
        String scriptPath = (String) arguments.get("script_path");
        String scriptArgsStr = (String) arguments.get("script_args");

        // Require at least one of script_name or script_path
        if ((scriptName == null || scriptName.trim().isEmpty()) &&
            (scriptPath == null || scriptPath.trim().isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either script_name or script_path is required")
                .build();
        }

        // Parse script arguments
        String[] scriptArgs = new String[0];
        if (scriptArgsStr != null && !scriptArgsStr.trim().isEmpty()) {
            scriptArgs = scriptArgsStr.split(",");
            for (int i = 0; i < scriptArgs.length; i++) {
                scriptArgs[i] = scriptArgs[i].trim();
            }
        }

        // Resolve script file
        ResourceFile scriptFile;
        try {
            scriptFile = resolveScript(scriptName, scriptPath);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error resolving script: " + e.getMessage())
                .build();
        }

        // Get the active plugin for tool/state access
        GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
        if (plugin == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No active plugin available. Make sure Ghidra has focus.")
                .build();
        }

        PluginTool tool = plugin.getTool();
        if (tool == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No tool available from plugin")
                .build();
        }

        // Capture output
        StringWriter outputWriter = new StringWriter();
        StringWriter errorWriter = new StringWriter();
        PrintWriter output = new PrintWriter(outputWriter);
        PrintWriter error = new PrintWriter(errorWriter);

        String scriptFilename = scriptFile.getName();
        boolean success = false;
        Exception scriptException = null;

        try {
            // Get script provider for this script type
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
            if (provider == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No script provider found for: " + scriptFilename +
                                  ". Supported types: .java, .py")
                    .build();
            }

            // Create script instance
            GhidraScript script = provider.getScriptInstance(scriptFile, output);
            if (script == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to create script instance for: " + scriptFilename)
                    .build();
            }

            // Create GhidraState with current context
            Address currentAddr = plugin.getCurrentAddress();
            ghidra.program.util.ProgramLocation location = null;
            if (currentAddr != null) {
                location = new ghidra.program.util.ProgramLocation(currentProgram, currentAddr);
            }

            GhidraState state = new GhidraState(
                tool,
                tool.getProject(),
                currentProgram,
                location,
                null, // selection
                null  // highlight
            );

            // Initialize script with state
            script.set(state, TaskMonitor.DUMMY, output);

            // Set script arguments if provided
            if (scriptArgs.length > 0) {
                script.setScriptArgs(scriptArgs);
            }

            // Execute script within a transaction on the Swing EDT to ensure synchronous completion
            // Use a latch to wait for completion since Ghidra scripts must run on EDT
            final CountDownLatch completionLatch = new CountDownLatch(1);
            final AtomicReference<Exception> scriptError = new AtomicReference<>();
            final AtomicReference<Boolean> scriptSuccess = new AtomicReference<>(false);

            // Capture these for use in the Runnable
            final GhidraScript finalScript = script;
            final GhidraState finalState = state;
            final PrintWriter finalOutput = output;
            final String finalScriptFilename = scriptFilename;
            final Program finalProgram = currentProgram;

            Runnable scriptRunner = () -> {
                int transactionID = finalProgram.startTransaction("Run Script: " + finalScriptFilename);
                try {
                    // Use execute() method which is public, unlike run() which is protected
                    finalScript.execute(finalState, TaskMonitor.DUMMY, finalOutput);
                    finalProgram.endTransaction(transactionID, true);
                    scriptSuccess.set(true);
                } catch (Exception e) {
                    finalProgram.endTransaction(transactionID, false);
                    scriptError.set(e);
                    Msg.error(this, "Script execution failed: " + e.getMessage(), e);
                } finally {
                    completionLatch.countDown();
                }
            };

            // Run on EDT and wait for completion
            if (SwingUtilities.isEventDispatchThread()) {
                // Already on EDT, run directly
                scriptRunner.run();
            } else {
                // Schedule on EDT and wait
                SwingUtilities.invokeLater(scriptRunner);
                try {
                    // Wait up to 10 minutes for script completion
                    if (!completionLatch.await(10, TimeUnit.MINUTES)) {
                        scriptException = new RuntimeException("Script execution timed out after 10 minutes");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    scriptException = e;
                }
            }

            // Get results from atomic references
            if (scriptError.get() != null) {
                scriptException = scriptError.get();
            }
            success = scriptSuccess.get();

        } catch (Exception e) {
            scriptException = e;
            Msg.error(this, "Script setup failed: " + e.getMessage(), e);
        }

        // Build result
        StringBuilder result = new StringBuilder();
        result.append("Script Execution Report\n");
        result.append("=======================\n\n");
        result.append("Script: ").append(scriptFilename).append("\n");
        result.append("Path: ").append(scriptFile.getAbsolutePath()).append("\n");
        if (scriptArgs.length > 0) {
            result.append("Arguments: ").append(String.join(", ", scriptArgs)).append("\n");
        }
        result.append("Status: ").append(success ? "SUCCESS" : "FAILED").append("\n\n");

        String stdout = outputWriter.toString();
        String stderr = errorWriter.toString();

        if (!stdout.isEmpty()) {
            result.append("=== Output ===\n");
            result.append(stdout);
            if (!stdout.endsWith("\n")) {
                result.append("\n");
            }
            result.append("\n");
        }

        if (!stderr.isEmpty()) {
            result.append("=== Errors ===\n");
            result.append(stderr);
            if (!stderr.endsWith("\n")) {
                result.append("\n");
            }
            result.append("\n");
        }

        if (scriptException != null) {
            result.append("=== Exception ===\n");
            result.append(scriptException.getClass().getName()).append(": ");
            result.append(scriptException.getMessage()).append("\n");

            // Include cause if present
            Throwable cause = scriptException.getCause();
            if (cause != null) {
                result.append("Caused by: ").append(cause.getClass().getName());
                result.append(": ").append(cause.getMessage()).append("\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Resolve script by name or path.
     */
    private ResourceFile resolveScript(String scriptName, String scriptPath) throws Exception {
        // Priority 1: Explicit path
        if (scriptPath != null && !scriptPath.trim().isEmpty()) {
            File file = new File(scriptPath.trim());
            if (!file.exists()) {
                throw new IllegalArgumentException("Script file not found: " + scriptPath);
            }
            if (!file.isFile()) {
                throw new IllegalArgumentException("Path is not a file: " + scriptPath);
            }
            return new ResourceFile(file);
        }

        // Priority 2: Search by name in Ghidra script directories
        if (scriptName != null && !scriptName.trim().isEmpty()) {
            scriptName = scriptName.trim();

            // Try to find script by name using GhidraScriptUtil
            ResourceFile found = GhidraScriptUtil.findScriptByName(scriptName);
            if (found != null) {
                return found;
            }

            // Try with .java extension if not present
            if (!scriptName.endsWith(".java") && !scriptName.endsWith(".py")) {
                found = GhidraScriptUtil.findScriptByName(scriptName + ".java");
                if (found != null) {
                    return found;
                }
                found = GhidraScriptUtil.findScriptByName(scriptName + ".py");
                if (found != null) {
                    return found;
                }
            }

            // List available script directories for help message
            StringBuilder dirs = new StringBuilder();
            dirs.append("Script '").append(scriptName).append("' not found.\n\n");
            dirs.append("Searched directories:\n");
            List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
            for (ResourceFile dir : scriptDirs) {
                dirs.append("  ").append(dir.getAbsolutePath()).append("\n");
            }
            dirs.append("\nTip: Place scripts in ~/ghidra_scripts/ or provide full path via script_path parameter.");
            throw new IllegalArgumentException(dirs.toString());
        }

        throw new IllegalArgumentException("Either script_name or script_path must be provided");
    }
}
