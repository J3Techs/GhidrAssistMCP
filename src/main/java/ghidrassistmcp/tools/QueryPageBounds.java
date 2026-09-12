package ghidrassistmcp.tools;

import java.math.BigDecimal;
import java.util.Map;

/** Shared, exact integer validation for bounded legacy read queries. */
final class QueryPageBounds {
    static final int MAX_LIMIT = 1000;

    private QueryPageBounds() {}

    static int integer(Map<String, Object> args, String name, int fallback, int min, int max) {
        if (!args.containsKey(name)) return fallback;
        Object value = args.get(name);
        if (value instanceof Number number) {
            try {
                int parsed = new BigDecimal(number.toString()).intValueExact();
                if (parsed >= min && parsed <= max) return parsed;
            } catch (NumberFormatException | ArithmeticException ignored) {
                // NaN, infinity, fractions, and overflow are invalid JSON-schema integers.
            }
        }
        throw new IllegalArgumentException(name + " must be an integer from " + min + " to " + max);
    }

    static Map<String, Object> limitSchema() {
        return Map.of("type", "integer", "minimum", 1, "maximum", MAX_LIMIT,
            "default", 100, "description", "Maximum results per page (1-1000; default 100)");
    }

    static Map<String, Object> offsetSchema() {
        return Map.of("type", "integer", "minimum", 0, "maximum", Integer.MAX_VALUE,
            "default", 0, "description", "Number of matching results to skip (default 0)");
    }

    static io.modelcontextprotocol.spec.McpSchema.CallToolResult result(String summary, Map<String, Object> page) {
        var json = ProjectToolSupport.result(page);
        var content = new java.util.ArrayList<io.modelcontextprotocol.spec.McpSchema.Content>();
        content.add(new io.modelcontextprotocol.spec.McpSchema.TextContent(summary));
        content.addAll(json.content());
        return io.modelcontextprotocol.spec.McpSchema.CallToolResult.builder().content(content)
            .isError(json.isError()).structuredContent(json.structuredContent()).build();
    }

    static Map<String, Object> outputSchema(String collection, Map<String, Object> itemProperties) {
        return Map.of("type", "object", "properties", Map.of(
            collection, Map.of("type", "array", "maxItems", MAX_LIMIT, "items",
                Map.of("type", "object", "properties", itemProperties, "required", java.util.List.copyOf(itemProperties.keySet()))),
            "count", Map.of("type", "integer", "minimum", 0, "maximum", MAX_LIMIT),
            "offset", Map.of("type", "integer", "minimum", 0),
            "limit", Map.of("type", "integer", "minimum", 1, "maximum", MAX_LIMIT),
            "has_more", Map.of("type", "boolean"),
            "next_offset", Map.of("type", java.util.List.of("integer", "null"), "minimum", 0)),
            "required", java.util.List.of(collection, "count", "offset", "limit", "has_more", "next_offset"));
    }
}
