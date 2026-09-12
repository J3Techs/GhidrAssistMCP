package ghidrassistmcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;

/** Preserve the structured result as a standalone JSON text block for text-only clients. */
public final class McpResultContent {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private McpResultContent() {}

    public static McpSchema.CallToolResult withJsonFallback(McpSchema.CallToolResult result) {
        if (result == null || result.structuredContent() == null) return result;
        try {
            String serialized = MAPPER.writeValueAsString(result.structuredContent());
            var expected = MAPPER.readTree(serialized);
            var builder = McpSchema.CallToolResult.builder().isError(result.isError())
                .structuredContent(result.structuredContent());
            if (result.meta() != null) builder.meta(result.meta());
            boolean found = false;
            for (var content : result.content()) {
                if (content instanceof McpSchema.TextContent text) {
                    String candidate = text.text();
                    int prefixEnd = candidate.startsWith("[Context] ") ? candidate.indexOf("\n\n") : -1;
                    String json = prefixEnd >= 0 ? candidate.substring(prefixEnd + 2) : candidate;
                    boolean matches;
                    try { matches = expected.equals(MAPPER.readTree(json)); }
                    catch (Exception ignored) { matches = false; }
                    if (matches) {
                        found = true;
                        if (prefixEnd >= 0) {
                            builder.addTextContent(candidate.substring(0, prefixEnd));
                            builder.addTextContent(json);
                            continue;
                        }
                    }
                }
                builder.addContent(content);
            }
            if (!found) builder.addTextContent(serialized);
            return builder.build();
        } catch (Exception error) {
            return McpSchema.CallToolResult.builder().isError(true)
                .addTextContent("Unable to serialize structured tool result.").build();
        }
    }
}
