/*
 * MCP tool for listing async tasks.
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
 * MCP tool that lists all async tasks and their status.
 */
public class ListTasksTool implements McpTool {

    @Override
    public String getName() {
        return "list_tasks";
    }

    @Override
    public String getDescription() {
        return "List all async tasks with their status";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "status", Map.of(
                    "type", "string",
                    "description", "Optional: filter tasks by status",
                    "enum", List.of("PENDING", "RUNNING", "CANCEL_REQUESTED", "COMPLETED", "FAILED", "CANCELLED")
                ),
                "offset", Map.of("type", "integer", "minimum", 0, "default", 0),
                "limit", Map.of("type", "integer", "minimum", 1, "maximum", 100, "default", 20)
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return TaskResultSchemas.error("BACKEND_UNAVAILABLE",
            "Task listing requires backend reference. Use execute with backend parameter.", true);
    }

    @Override public Map<String, Object> getOutputSchema() { return TaskResultSchemas.listSchema(); }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        var taskManager = backend == null ? null : backend.getTaskManager();
        if (taskManager == null) {
            return TaskResultSchemas.error("BACKEND_UNAVAILABLE", "Task manager not available", true);
        }

        // Check for optional status filter
        if (arguments.containsKey("status") && !(arguments.get("status") instanceof String))
            return error("status must be a string");
        String statusStr = (String) arguments.get("status");
        McpTask.Status statusFilter = null;

        if (statusStr != null && !statusStr.trim().isEmpty()) {
            try {
                statusFilter = McpTask.Status.valueOf(statusStr.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException e) {
                return error("Invalid status filter: " + statusStr +
                        ". Valid values: PENDING, RUNNING, CANCEL_REQUESTED, COMPLETED, FAILED, CANCELLED");
            }
        }

        int offset, limit;
        try {
            offset = pageInteger(arguments, "offset", 0, 0, Integer.MAX_VALUE);
            limit = pageInteger(arguments, "limit", 20, 1, 100);
        } catch (IllegalArgumentException e) { return error(e.getMessage()); }
        List<McpTask> tasks = taskManager.listTasks(statusFilter).stream()
            .sorted(java.util.Comparator.comparing(McpTask::getCreatedAt).reversed()
                .thenComparing(McpTask::getTaskId)).toList();
        List<Map<String, Object>> page = tasks.stream().skip(offset).limit(limit)
            .map(McpTask::snapshot).toList();
        int nextOffset = Math.min(tasks.size(), offset) + page.size();
        Map<String, Object> data = new java.util.LinkedHashMap<>();
        data.put("schema_version", 1);
        data.put("manager_instance_id", taskManager.getInstanceId());
        data.put("tasks", page);
        data.put("total", tasks.size());
        data.put("offset", offset);
        data.put("returned", page.size());
        data.put("omitted", tasks.size() - page.size());
        data.put("has_more", nextOffset < tasks.size());
        if (nextOffset < tasks.size()) data.put("next_offset", nextOffset);
        StringBuilder summary = new StringBuilder("MCP Tasks: " + tasks.size() + ", returned " + page.size() + "\n");
        for (Map<String, Object> item : page) {
            summary.append(item.get("task_id")).append(" | ").append(item.get("tool_name"))
                .append(" | ").append(item.get("status")).append("\n");
        }
        return TaskResultSchemas.success(summary.toString(), data);
    }

    private static int pageInteger(Map<String, Object> args, String key, int fallback, int min, int max) {
        if (!args.containsKey(key)) return fallback;
        Object value = args.get(key);
        if (!(value instanceof Number)) throw new IllegalArgumentException(key + " must be an integer");
        try {
            int parsed = new java.math.BigDecimal(value.toString()).intValueExact();
            if (parsed < min || parsed > max) throw new ArithmeticException();
            return parsed;
        } catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalArgumentException(key + " must be an integer between " + min + " and " + max);
        }
    }

    private static McpSchema.CallToolResult error(String message) {
        return TaskResultSchemas.error("INVALID_ARGUMENT", message, false);
    }
}
