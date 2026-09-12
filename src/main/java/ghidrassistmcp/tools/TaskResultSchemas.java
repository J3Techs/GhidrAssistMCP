package ghidrassistmcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidrassistmcp.McpOutputSchemas;
import io.modelcontextprotocol.spec.McpSchema;

/** Concrete custom-task result contracts. These are not protocol Task objects. */
final class TaskResultSchemas {
    private static final ObjectMapper JSON = new ObjectMapper();
    private TaskResultSchemas() {}

    static Map<String, Object> waitSchema() {
        return withErrors(extend(McpOutputSchemas.taskSubmission(), Map.of(
            "wait_outcome", Map.of("type", "string", "enum", List.of("terminal", "changed", "timeout")),
            "result_status", Map.of("type", "string", "enum", List.of("included", "not_ready", "unavailable", "too_large")),
            "result_bytes", Map.of("type", "integer", "minimum", 0),
            "operation_result", Map.of("type", "object")),
            List.of("wait_outcome")));
    }

    /** Include a complete operation result, or explicit omission metadata; never slice JSON. */
    static void includeResult(Map<String, Object> snapshot, ghidrassistmcp.tasks.McpTask task, int budget) {
        if (!Boolean.TRUE.equals(snapshot.get("terminal"))) {
            snapshot.put("result_status", "not_ready"); return;
        }
        var payload = task == null ? null : task.getResult();
        if (payload == null) { snapshot.put("result_status", "unavailable"); return; }
        try {
            Map<String, Object> value = JSON.convertValue(payload, new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {});
            long size = JSON.writeValueAsBytes(value).length;
            snapshot.put("result_bytes", size);
            snapshot.put("result_status", "included");
            snapshot.put("operation_result", value);
            // Account for the outer structured body and its JSON text fallback including escaping.
            var candidate = success("Task result included.", snapshot);
            if (JSON.writeValueAsBytes(candidate).length + 1024 > budget) {
                snapshot.remove("operation_result"); snapshot.put("result_status", "too_large");
            }
        } catch (RuntimeException | JsonProcessingException error) {
            snapshot.remove("operation_result"); snapshot.put("result_status", "unavailable");
        }
    }

    static Map<String, Object> cancelSchema() {
        return withErrors(extend(McpOutputSchemas.taskSubmission(), Map.of(
            "cancellation_requested", Map.of("type", "boolean", "const", true)),
            List.of("cancellation_requested")));
    }

    static Map<String, Object> listSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("schema_version", Map.of("type", "integer", "const", 1));
        properties.put("manager_instance_id", Map.of("type", "string", "minLength", 1));
        properties.put("tasks", Map.of("type", "array", "maxItems", 100, "items", McpOutputSchemas.taskSnapshot()));
        for (String key : List.of("total", "offset", "returned", "omitted"))
            properties.put(key, Map.of("type", "integer", "minimum", 0));
        properties.put("returned", Map.of("type", "integer", "minimum", 0, "maximum", 100));
        properties.put("has_more", Map.of("type", "boolean"));
        properties.put("next_offset", Map.of("type", "integer", "minimum", 0));
        return withErrors(Map.of("type", "object", "properties", properties, "additionalProperties", false,
            "required", List.of("schema_version", "manager_instance_id", "tasks", "total", "offset", "returned", "omitted", "has_more"),
            "allOf", List.of(Map.of("if", Map.of("properties", Map.of("has_more", Map.of("const", true))),
                "then", Map.of("required", List.of("next_offset")),
                "else", Map.of("not", Map.of("required", List.of("next_offset")))))));
    }

    static Map<String, Object> withErrors(Map<String, Object> success) {
        return Map.of("type", "object", "oneOf", List.of(success, errorSchema()));
    }

    private static Map<String, Object> errorSchema() {
        return Map.of("type", "object", "additionalProperties", false,
            "properties", Map.of("schema_version", Map.of("type", "integer", "const", 1),
                "error", Map.of("type", "object", "additionalProperties", false,
                    "properties", Map.of(
                        "code", Map.of("type", "string", "enum", List.of("INVALID_ARGUMENT", "TASK_NOT_FOUND",
                            "BACKEND_UNAVAILABLE", "WAIT_INTERRUPTED", "CANCELLATION_NOT_ACCEPTED")),
                        "message", Map.of("type", "string", "maxLength", 2048),
                        "retryable", Map.of("type", "boolean")),
                    "required", List.of("code", "message", "retryable"))),
            "required", List.of("schema_version", "error"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> extend(Map<String, Object> base, Map<String, Object> extra,
            List<String> extraRequired) {
        Map<String, Object> schema = new LinkedHashMap<>(base);
        Map<String, Object> properties = new LinkedHashMap<>((Map<String, Object>) base.get("properties"));
        properties.putAll(extra);
        var required = new java.util.ArrayList<>((List<String>) base.get("required"));
        required.addAll(extraRequired);
        schema.put("properties", properties);
        schema.put("required", required);
        return schema;
    }

    static McpSchema.CallToolResult error(String code, String message, boolean retryable) {
        String bounded = message.substring(0, Math.min(message.length(), 2048));
        return result(bounded, Map.of("schema_version", 1,
            "error", Map.of("code", code, "message", bounded, "retryable", retryable)), true);
    }

    static McpSchema.CallToolResult success(String text, Map<String, Object> data) {
        return result(text, data, false);
    }

    private static McpSchema.CallToolResult result(String text, Map<String, Object> data, boolean error) {
        try {
            return McpSchema.CallToolResult.builder().isError(error).structuredContent(data)
                .addTextContent(text).addTextContent(JSON.writeValueAsString(data)).build();
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Custom task metadata could not be serialized", e);
        }
    }
}
