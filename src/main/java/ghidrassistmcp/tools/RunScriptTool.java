/*
 * RunScriptTool - Execute GhidraScripts programmatically with output capture
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

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
import ghidra.app.script.ScriptControls;
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
    public boolean isOpenWorld() {
        return true; // User scripts may access filesystem, processes, and network services.
    }

    private static final int DEFAULT_TIMEOUT_MINUTES = 10;
    private static final int DEFAULT_MAX_OUTPUT_CHARS = 200_000;
    private static final ReentrantLock SCRIPT_LOCK = new ReentrantLock();
    private static volatile String activeScriptName = null;

    @Override
    public String getName() {
        return "run_script";
    }

    @Override
    public String getDescription() {
        return "Execute a GhidraScript by name or path. " +
               "Searches Ghidra script directories if only name is provided. " +
               "Supports Java (.java) and Python (.py) scripts. " +
               "Returns captured stdout and stderr output. Runs off the EDT by default; run_on_edt=true is available for UI scripts. " +
               "timeout_minutes (default 10, 0 disables) requests cooperative cancellation; ownership is retained until the script stops.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "script_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "script_path", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "script_args", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "timeout_minutes", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "run_on_edt", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "max_output_chars", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // This tool needs the backend to access plugin/tool context
        return McpSchema.CallToolResult.builder()
            .isError(true).addTextContent("This tool requires backend context for script execution. " +
                          "Please ensure the MCP server is properly connected.")
            .build();
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        return execute(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No program currently loaded")
                .build();
        }

        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Backend context not available")
                .build();
        }

        // Get parameters
        String scriptName = (String) arguments.get("script_name");
        String scriptPath = (String) arguments.get("script_path");
        Object scriptArgsObj = arguments.get("script_args");
        int timeoutMinutes = getIntArg(arguments, "timeout_minutes", DEFAULT_TIMEOUT_MINUTES);
        boolean runOnEdt = getBooleanArg(arguments, "run_on_edt", false);
        int maxOutputChars = getIntArg(arguments, "max_output_chars", DEFAULT_MAX_OUTPUT_CHARS);
        if (timeoutMinutes < 0 || timeoutMinutes > 1440)
            return McpSchema.CallToolResult.builder().isError(true).addTextContent("timeout_minutes must be between 0 and 1440").build();
        TaskMonitor monitor = task == null ? new ghidra.util.task.TaskMonitorAdapter(true)
            : new ghidrassistmcp.tasks.McpTaskMonitor(task, 0, 100, "Running script");

        // Require at least one of script_name or script_path
        if ((scriptName == null || scriptName.trim().isEmpty()) &&
            (scriptPath == null || scriptPath.trim().isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Either script_name or script_path is required")
                .build();
        }

        // Parse script arguments (string or list)
        String[] scriptArgs = parseScriptArgs(scriptArgsObj);

        // Resolve script file
        ResourceFile scriptFile;
        try {
            scriptFile = resolveScript(scriptName, scriptPath);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Error resolving script: " + e.getMessage())
                .build();
        }

        // Get the active plugin for tool/state access
        GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
        if (plugin == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No active plugin available. Make sure Ghidra has focus.")
                .build();
        }

        PluginTool tool = plugin.getTool();
        if (tool == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No tool available from plugin")
                .build();
        }

        // Prevent concurrent script execution
        if (!SCRIPT_LOCK.tryLock()) {
            String running = activeScriptName != null ? activeScriptName : "unknown";
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Another script is already running: " + running +
                    "\nCancel the running task or wait for completion before starting a new script.")
                .build();
        }

        String scriptFilename = scriptFile.getName();
        boolean success = false;
        Exception scriptException = null;
        LimitedWriter outputWriter = null;
        LimitedWriter errorWriter = null;

        try {
            activeScriptName = scriptFilename;

            // Capture output with size limits
            int outLimit = maxOutputChars > 0 ? maxOutputChars : DEFAULT_MAX_OUTPUT_CHARS;
            outputWriter = new LimitedWriter(outLimit);
            errorWriter = new LimitedWriter(outLimit);
            PrintWriter output = new PrintWriter(outputWriter, true);
            PrintWriter error = new PrintWriter(errorWriter, true);

            // Get script provider for this script type
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
            if (provider == null) {
                return McpSchema.CallToolResult.builder()
                    .isError(true).addTextContent("No script provider found for: " + scriptFilename +
                                  ". Supported types: .java, .py")
                    .build();
            }

            // Create script instance
            GhidraScript script = provider.getScriptInstance(scriptFile, output);
            if (script == null) {
                return McpSchema.CallToolResult.builder()
                    .isError(true).addTextContent("Failed to create script instance for: " + scriptFilename)
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

            // Create ScriptControls with output/error writers and task monitor
            ScriptControls controls = new ScriptControls(output, error, monitor);

            // Initialize script with state using new API
            script.set(state, controls);

            // Set script arguments if provided
            if (scriptArgs.length > 0) {
                script.setScriptArgs(scriptArgs);
            }

            ghidrassistmcp.tasks.OwnedScriptExecution.run(() -> {
                monitor.checkCancelled();
                int transactionID = currentProgram.startTransaction("Run Script: " + scriptFilename);
                boolean commit = false;
                try {
                    script.execute(state, controls);
                    monitor.checkCancelled();
                    commit = true;
                } finally { currentProgram.endTransaction(transactionID, commit); }
            }, monitor, timeoutMinutes > 0 ? java.time.Duration.ofMinutes(timeoutMinutes) : java.time.Duration.ZERO,
                task, runOnEdt);
            success = true;
        } catch (Exception e) {
            propagateTaskCancellation(task, monitor, e);
            scriptException = e;
            Msg.error(this, "Script execution failed: " + e.getMessage(), e);
        }
        finally {
            activeScriptName = null;
            SCRIPT_LOCK.unlock();
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

        String stdout = outputWriter != null ? outputWriter.getValue() : "";
        String stderr = errorWriter != null ? errorWriter.getValue() : "";
        boolean outTruncated = outputWriter != null && outputWriter.isTruncated();
        boolean errTruncated = errorWriter != null && errorWriter.isTruncated();

        if (!stdout.isEmpty()) {
            result.append("=== Output ===\n");
            result.append(stdout);
            if (!stdout.endsWith("\n")) {
                result.append("\n");
            }
            if (outTruncated) {
                result.append("[output truncated]\n");
            }
            result.append("\n");
        }

        if (!stderr.isEmpty()) {
            result.append("=== Errors ===\n");
            result.append(stderr);
            if (!stderr.endsWith("\n")) {
                result.append("\n");
            }
            if (errTruncated) {
                result.append("[error output truncated]\n");
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
            .isError(!success).addTextContent(result.toString())
            .build();
    }

    /** Preserve the async manager's cancellation state after the script runner has settled. */
    static void propagateTaskCancellation(ghidrassistmcp.tasks.McpTask task, TaskMonitor monitor, Exception failure) {
        if (task != null && monitor.isCancelled()) {
            var cancelled = new java.util.concurrent.CancellationException("Script cancelled after its runner stopped");
            cancelled.initCause(failure);
            throw cancelled;
        }
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

    private static int getIntArg(Map<String, Object> arguments, String key, int defaultValue) {
        Object val = arguments.get(key);
        if (val instanceof Number) {
            return ((Number) val).intValue();
        }
        if (val instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static boolean getBooleanArg(Map<String, Object> arguments, String key, boolean defaultValue) {
        Object val = arguments.get(key);
        if (val instanceof Boolean) {
            return (Boolean) val;
        }
        if (val instanceof String s) {
            return Boolean.parseBoolean(s.trim());
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    private static String[] parseScriptArgs(Object scriptArgsObj) {
        if (scriptArgsObj == null) {
            return new String[0];
        }
        if (scriptArgsObj instanceof List<?> list) {
            return list.stream().map(Object::toString).toArray(String[]::new);
        }
        if (scriptArgsObj instanceof String s) {
            if (s.trim().isEmpty()) {
                return new String[0];
            }
            String[] parts = s.split(",");
            for (int i = 0; i < parts.length; i++) {
                parts[i] = parts[i].trim();
            }
            return parts;
        }
        return new String[] { scriptArgsObj.toString() };
    }

    private static final class LimitedWriter extends Writer {
        private final int maxChars;
        private final StringBuilder sb = new StringBuilder();
        private boolean truncated = false;

        private LimitedWriter(int maxChars) {
            this.maxChars = Math.max(1024, maxChars);
        }

        @Override
        public void write(char[] cbuf, int off, int len) {
            if (truncated || len <= 0) {
                return;
            }
            int remaining = maxChars - sb.length();
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            int toWrite = Math.min(len, remaining);
            sb.append(cbuf, off, toWrite);
            if (toWrite < len) {
                truncated = true;
            }
        }

        @Override
        public void write(String str, int off, int len) {
            if (str == null || truncated || len <= 0) {
                return;
            }
            int remaining = maxChars - sb.length();
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            int toWrite = Math.min(len, remaining);
            sb.append(str, off, off + toWrite);
            if (toWrite < len) {
                truncated = true;
            }
        }

        @Override
        public void write(int c) {
            if (truncated) {
                return;
            }
            int remaining = maxChars - sb.length();
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            sb.append((char) c);
        }

        @Override
        public void flush() {
            // no-op
        }

        @Override
        public void close() {
            // no-op
        }

        public String getValue() {
            return sb.toString();
        }

        public boolean isTruncated() {
            return truncated;
        }
    }
}
