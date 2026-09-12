/*
 * MCP tool for getting task status.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets the status of an async task or retrieves its result.
 */
public class GetTaskStatusTool implements McpTool {

    @Override
    public String getName() {
        return "get_task_status";
    }

    @Override
    public String getDescription() {
        return "Get the status of an async task, or retrieve its result if completed";
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
        return McpSchema.CallToolResult.builder()
            .isError(true)
            .addTextContent("Task status requires backend reference. Use execute with backend parameter.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String taskId = arguments.get("task_id") instanceof String id ? id : null;

        if (taskId == null || taskId.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("task_id parameter is required")
                .build();
        }

        var taskManager = backend.getTaskManager();
        if (taskManager == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task manager not available")
                .build();
        }

        McpTask task = taskManager.getTask(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task not found: " + taskId)
                .build();
        }

        // Return the retained operation payload for both successful and error outcomes.
        McpSchema.CallToolResult retained = task.getResult();
        if (task.isTerminal() && retained != null) {
            return retained;
        }

        if (task.isTerminal() && task.getResultRetentionCode() != null) {
            return ProjectToolSupport.result(Map.of(
                "error", Map.of("code", task.getResultRetentionCode(),
                    "message", "The terminal task payload is no longer retained; operation status is authoritative."),
                "task_id", task.getTaskId(), "operation_status", task.getStatus().name(),
                "result_available", false, "retained_result_bytes", task.getRetainedResultBytes()), true);
        }

        // Otherwise return status summary
        return McpSchema.CallToolResult.builder()
            .isError(task.getStatus() == McpTask.Status.FAILED || task.getStatus() == McpTask.Status.CANCELLED)
            .addTextContent(task.toSummary())
            .build();
    }
}
