package ghidrassistmcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import io.modelcontextprotocol.spec.McpSchema;

/** Adapts legacy tool schemas without discarding modern keywords in map-based schemas. */
public final class McpSchemas {
    private McpSchemas() {}

    public static Map<String, Object> fromLegacy(McpSchema.JsonSchema schema) {
        if (schema == null) return Map.of("type", "object", "properties", Map.of());
        Map<String, Object> result = new LinkedHashMap<>();
        put(result, "type", schema.type());
        put(result, "properties", schema.properties());
        put(result, "required", schema.required());
        put(result, "additionalProperties", schema.additionalProperties());
        put(result, "$defs", schema.defs());
        put(result, "definitions", schema.definitions());
        return result;
    }

    private static void put(Map<String, Object> result, String key, Object value) {
        if (value != null) result.put(key, normalize(value));
    }

    private static Object normalize(Object value) {
        if (value instanceof McpSchema.JsonSchema schema) return fromLegacy(schema);
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            map.forEach((key, item) -> normalized.put(String.valueOf(key), normalize(item)));
            return normalized;
        }
        if (value instanceof List<?> list) return list.stream().map(McpSchemas::normalize).toList();
        return value;
    }
}
