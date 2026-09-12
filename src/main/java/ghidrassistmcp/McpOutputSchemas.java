package ghidrassistmcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

/** Concrete completion contracts and the separate application-task submission contract. */
public final class McpOutputSchemas {
    private McpOutputSchemas() {}

    public static Map<String, Object> taskSnapshot() {
        Map<String, Object> properties = new LinkedHashMap<>();
        var text = Map.of("type", "string");
        var clipped = Map.of("type", "string", "maxLength", 2048);
        var nonnegative = Map.of("type", "integer", "minimum", 0);
        properties.put("retained_result_bytes", nonnegative);
        properties.put("result_retention_code", Map.of("type", "string", "enum", List.of("RESULT_EXPIRED", "RESULT_TOO_LARGE")));
        for (String key : List.of("task_id", "created_at", "started_at", "completed_at")) properties.put(key, text);
        for (String key : List.of("tool_name", "progress_message", "error_message")) properties.put(key, clipped);
        for (String key : List.of("state_version", "duration_ms")) properties.put(key, nonnegative);
        for (String key : List.of("terminal", "result_available", "metadata_truncated")) properties.put(key, Map.of("type", "boolean"));
        properties.put("progress_percent", Map.of("type", "integer", "minimum", 0, "maximum", 100));
        properties.put("status", Map.of("type", "string", "enum", List.of("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCEL_REQUESTED", "CANCELLED")));
        properties.put("program", Map.of("type", "object", "properties", Map.of(
            "name", clipped, "project_path", clipped, "file_id", clipped, "program_id", clipped), "additionalProperties", false));
        return Map.of("type", "object", "properties", properties, "required", List.of(
            "task_id", "tool_name", "state_version", "status", "terminal", "progress_percent", "progress_message",
            "created_at", "duration_ms", "result_available", "program", "metadata_truncated"), "additionalProperties", false);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> taskSubmission() {
        var base = taskSnapshot();
        Map<String, Object> properties = new LinkedHashMap<>((Map<String, Object>) base.get("properties"));
        properties.put("schema_version", Map.of("type", "integer", "const", 1));
        properties.put("manager_instance_id", Map.of("type", "string", "minLength", 1));
        properties.put("lifecycle", Map.of("type", "string", "const", "custom_in_memory"));
        properties.put("result_tool", Map.of("type", "string", "const", "get_task_status"));
        var required = new ArrayList<>((List<String>) base.get("required"));
        required.addAll(List.of("schema_version", "manager_instance_id", "lifecycle", "result_tool"));
        return Map.of("type", "object", "properties", properties, "required", required, "additionalProperties", false);
    }

    /** The completed operation schema remains independent from its optional async submission. */
    public static Map<String, Object> advertised(McpTool tool) {
        var completion = tool.getOutputSchema();
        if (completion == null || !tool.isLongRunning()) return completion;
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("anyOf", List.of(completion, taskSubmission()));
        // Preserve root references when embedding the completion contract in the union.
        for (String key : List.of("$defs", "definitions", "$schema", "$id"))
            if (completion.containsKey(key)) schema.put(key, completion.get(key));
        return schema;
    }

    /** Validate before caching or marking an asynchronous operation completed. */
    public static McpSchema.CallToolResult validateCompletion(McpTool tool, McpSchema.CallToolResult result) {
        if (result == null || Boolean.TRUE.equals(result.isError()) || tool.getOutputSchema() == null) return result;
        var validation = McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), result.structuredContent());
        if (validation.valid()) return result;
        return McpSchema.CallToolResult.builder().isError(true)
            .addTextContent("Tool output failed its declared schema: " + validation.errorMessage()).build();
    }
}
