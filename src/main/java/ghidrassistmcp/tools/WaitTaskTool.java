package ghidrassistmcp.tools;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.McpRequestContext;
import ghidrassistmcp.tasks.McpTaskManager;
import java.util.concurrent.TimeUnit;
import io.modelcontextprotocol.spec.McpSchema;

/** Bounded waiting for the existing custom async tool lifecycle. */
public final class WaitTaskTool implements McpTool {
    @Override public String getName() { return "wait_task"; }
    @Override public String getDescription() {
        return "Wait up to 30 seconds for a custom async task to finish, or for state_version to advance " +
            "when after_version is supplied. Timeout or interruption ends only this wait; the operation continues. " +
            "Returns bounded metadata; include_result=true also returns a complete terminal operation_result when it fits max_result_bytes. " +
            "Use get_task_status for an omitted retained result. " +
            "Task IDs and version cursors are in-memory and scoped to manager_instance_id. This is not the negotiated MCP Tasks extension.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "task_id", Map.of("type", "string", "minLength", 1),
            "include_result", Map.of("type", "boolean", "default", false),
            "max_result_bytes", Map.of("type", "integer", "minimum", 1024, "maximum", 1048576, "default", 65536),
            "timeout_ms", Map.of("type", "integer", "minimum", 0, "maximum", 30000, "default", 25000),
            "after_version", Map.of("type", "integer", "minimum", 0,
                "description", "Previously observed state_version for this task. Omit to wait for terminal state.")),
            List.of("task_id"), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        return TaskResultSchemas.waitSchema();
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        return TaskResultSchemas.error("BACKEND_UNAVAILABLE", "Task waiting requires a backend", true);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        try {
            if (!(arguments.get("task_id") instanceof String id) || id.isBlank())
                return TaskResultSchemas.error("INVALID_ARGUMENT", "task_id must be a nonblank string", false);
            long timeout = integer(arguments, "timeout_ms", 25000);
            if (arguments.containsKey("include_result") && !(arguments.get("include_result") instanceof Boolean))
                throw new IllegalArgumentException("include_result must be a boolean");
            long resultBudget = integer(arguments, "max_result_bytes", 65536);
            if (resultBudget < 1024 || resultBudget > 1048576)
                throw new IllegalArgumentException("max_result_bytes must be between 1024 and 1048576");
            Long afterVersion = arguments.containsKey("after_version") ? integer(arguments, "after_version", 0) : null;
            if (timeout < 0 || timeout > 30000) throw new IllegalArgumentException("timeout_ms must be between 0 and 30000");
            if (backend == null || backend.getTaskManager() == null)
                return TaskResultSchemas.error("BACKEND_UNAVAILABLE", "Task manager not available", true);
            if (backend.getTaskManager().getTask(id) == null)
                return TaskResultSchemas.error("TASK_NOT_FOUND", "Task not found: " + id, false);
            Map<String, Object> snapshot = waitWithProgress(backend.getTaskManager(), id, timeout, afterVersion);
            if (Boolean.TRUE.equals(arguments.get("include_result")))
                TaskResultSchemas.includeResult(snapshot, backend.getTaskManager().getTask(id), (int) resultBudget);
            return TaskResultSchemas.success("Task " + id + ": " + snapshot.get("status") + "; wait " + snapshot.get("wait_outcome") +
                    "; version " + snapshot.get("state_version") + ". Use get_task_status to retrieve a terminal result.", snapshot);
        } catch (IllegalArgumentException e) {
            return TaskResultSchemas.error("INVALID_ARGUMENT", e.getMessage(), false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return TaskResultSchemas.error("WAIT_INTERRUPTED", "Wait interrupted; the operation was not cancelled. Resume with wait_task or get_task_status.", true);
        }
    }
    private static long integer(Map<String, Object> args, String name, long defaultValue) {
        if (!args.containsKey(name)) return defaultValue;
        Object value = args.get(name);
        if (!(value instanceof Number)) throw new IllegalArgumentException(name + " must be an integer");
        try { return new BigDecimal(value.toString()).longValueExact(); }
        catch (ArithmeticException | NumberFormatException e) { throw new IllegalArgumentException(name + " must be an integer within signed 64-bit range"); }
    }
    /** Request progress describes this wait's elapsed time, never a detached worker's lifetime. */
    private static Map<String, Object> waitWithProgress(McpTaskManager manager, String id, long timeout, Long afterVersion)
            throws InterruptedException {
        if (!McpRequestContext.hasProgressReporter() || timeout == 0)
            return manager.waitForTask(id, timeout, afterVersion);
        final long start = System.nanoTime();
        final long deadline = start + TimeUnit.MILLISECONDS.toNanos(timeout);
        Map<String, Object> snapshot = manager.waitForTask(id, 0, afterVersion);
        if (!"timeout".equals(snapshot.get("wait_outcome"))) return snapshot;
        McpRequestContext.reportProgress(0, timeout / 1000.0, "Waiting for task " + id);
        long lastReport = start;
        while (!(Boolean) snapshot.get("terminal") &&
                (afterVersion == null || ((Number) snapshot.get("state_version")).longValue() <= afterVersion)) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) break;
            long slice = Math.min(250, Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
            snapshot = manager.waitForTask(id, slice, ((Number) snapshot.get("state_version")).longValue());
            long now = System.nanoTime();
            if (now - lastReport >= TimeUnit.MILLISECONDS.toNanos(250)) {
                reportWaitProgress(start, timeout, snapshot);
                lastReport = now;
            }
        }
        boolean terminal = Boolean.TRUE.equals(snapshot.get("terminal"));
        boolean changed = afterVersion != null && ((Number) snapshot.get("state_version")).longValue() > afterVersion;
        snapshot.put("wait_outcome", terminal ? "terminal" : changed ? "changed" : "timeout");
        reportWaitProgress(start, timeout, snapshot);
        return snapshot;
    }

    private static void reportWaitProgress(long start, long timeout, Map<String, Object> snapshot) {
        double elapsed = Math.min(timeout / 1000.0, (System.nanoTime() - start) / 1_000_000_000.0);
        McpRequestContext.reportProgress(elapsed, timeout / 1000.0,
            "Task " + snapshot.get("status") + ": " + snapshot.get("progress_percent") + "% - " + snapshot.get("progress_message"));
    }
}
