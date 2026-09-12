package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Locale;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class SearchStringsTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "search_strings"; }

    @Override
    public String getDescription() { return "Search defined strings by substring, with offset/limit pages and explicit has_more. Page against an unchanged program. Structured values are previewed to 256 characters with length and value_truncated; use get_data_at for full memory data."; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", Map.of("type", "string", "minLength", 1, "description", "Substring to match against string content (not a regular expression)"),
                "case_sensitive", Map.of("type", "boolean", "description", "Case sensitive search (default false)"),
                "offset", QueryPageBounds.offsetSchema(),
                "limit", QueryPageBounds.limitSchema()
            ),
            List.of("pattern"), null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        return QueryPageBounds.outputSchema("strings", Map.of(
            "address", Map.of("type", "string"), "value", Map.of("type", "string", "maxLength", 256),
            "length", Map.of("type", "integer", "minimum", 0), "value_truncated", Map.of("type", "boolean")));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent("No program currently loaded").build();
        }

        if (!(arguments.get("pattern") instanceof String pattern) || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent("pattern must be a nonempty string").build();
        }

        boolean caseSensitive = Boolean.TRUE.equals(arguments.get("case_sensitive"));
        final int limit;
        final int offset;
        try {
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
            offset = QueryPageBounds.integer(arguments, "offset", 0, 0, Integer.MAX_VALUE);
            if (arguments.containsKey("case_sensitive") && !(arguments.get("case_sensitive") instanceof Boolean))
                throw new IllegalArgumentException("case_sensitive must be a boolean");
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent(e.getMessage()).build();
        }

        String searchPattern = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);

        StringBuilder result = new StringBuilder();
        result.append("Strings matching \"").append(pattern).append("\":\n\n");

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        long skipped = 0;
        boolean hasMore = false;
        List<Map<String, Object>> rows = new ArrayList<>();

        while (dataIter.hasNext()) {
            if (Thread.currentThread().isInterrupted()) {
                return McpSchema.CallToolResult.builder().isError(true).addTextContent("String search interrupted").build();
            }
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                String text = extractStringText(stringValue);
                if (text != null) {
                    String compareText = caseSensitive ? text : text.toLowerCase(Locale.ROOT);
                    if (compareText.contains(searchPattern)) {
                        if (skipped++ < offset) continue;
                        if (count == limit) { hasMore = true; break; }
                        String display = stringValue.length() > 80 ? stringValue.substring(0, 77) + "..." : stringValue;
                        result.append("@ ").append(data.getAddress()).append(": ").append(display).append("\n");
                        count++;
                        rows.add(Map.of("address", data.getAddress().toString(), "value", text.substring(0, Math.min(text.length(), 256)),
                            "length", text.length(), "value_truncated", text.length() > 256));
                    }
                }
            }
        }

        if (count == 0) {
            result.append(offset == 0 ? "No strings found matching: " : "No further strings matching: ").append(pattern);
        } else {
            result.append("\nFound ").append(count).append(" matching strings");
        }

        if (hasMore) result.append("\nMore results available; next offset: ").append((long) offset + count);
        Map<String, Object> page = new LinkedHashMap<>();
        page.put("strings", rows);
        page.put("count", count);
        page.put("offset", offset);
        page.put("limit", limit);
        page.put("has_more", hasMore);
        page.put("next_offset", hasMore ? (long) offset + count : null);
        return QueryPageBounds.result(result.toString(), page);
    }

    private static String extractStringText(String repr) {
        if (repr == null) return null;
        int first = repr.indexOf('"');
        int last = repr.lastIndexOf('"');
        if (first >= 0 && last > first) return repr.substring(first + 1, last);
        return repr;
    }
}
