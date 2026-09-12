/*
 * MCP tool for cancelling async tasks.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that cancels a running async task.
 */
public class CancelTaskTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public String getName() {
        return "cancel_task";
    }

    @Override
    public String getDescription() {
        return "Request cancellation of a custom async task. Running workers settle cooperatively; check wait_task or get_task_status for the final outcome.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "task_id", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("task_id"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return TaskResultSchemas.error("BACKEND_UNAVAILABLE",
            "Task cancellation requires backend reference. Use execute with backend parameter.", true);
    }

    @Override public Map<String, Object> getOutputSchema() { return TaskResultSchemas.cancelSchema(); }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String taskId = arguments.get("task_id") instanceof String id ? id : null;

        if (taskId == null || taskId.trim().isEmpty()) {
            return TaskResultSchemas.error("INVALID_ARGUMENT", "task_id parameter is required", false);
        }

        var taskManager = backend == null ? null : backend.getTaskManager();
        if (taskManager == null) {
            return TaskResultSchemas.error("BACKEND_UNAVAILABLE", "Task manager not available", true);
        }

        var task = taskManager.getTask(taskId);
        if (task == null) return TaskResultSchemas.error("TASK_NOT_FOUND", "Task not found: " + taskId, false);

        boolean cancelled = taskManager.cancelTask(taskId);

        if (cancelled) {
            Map<String, Object> snapshot = taskManager.waitForTaskSnapshot(task);
            snapshot.put("cancellation_requested", true);
            return TaskResultSchemas.success("Cancellation requested for task: " + taskId + ". Current status: " +
                    snapshot.get("status") + ". Use wait_task to observe the final outcome.", snapshot);
        }
        return TaskResultSchemas.error("CANCELLATION_NOT_ACCEPTED", "Could not cancel task: " + taskId +
                ". Task may have already completed or cancellation was already requested.", false);
    }
}
