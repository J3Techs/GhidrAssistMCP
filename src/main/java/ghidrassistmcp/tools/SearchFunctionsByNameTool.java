package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Locale;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class SearchFunctionsByNameTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "search_functions_by_name"; }

    @Override
    public String getDescription() { return "Search function names by case-insensitive substring, with offset/limit pages and explicit has_more. Page against an unchanged program."; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "search_term", Map.of("type", "string", "minLength", 1, "description", "Search term to match against function names"),
                "offset", QueryPageBounds.offsetSchema(),
                "limit", QueryPageBounds.limitSchema()
            ),
            List.of("search_term"), null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        return QueryPageBounds.outputSchema("functions", Map.of(
            "name", Map.of("type", "string"), "address", Map.of("type", "string"),
            "parameter_count", Map.of("type", "integer", "minimum", 0)));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent("No program currently loaded").build();
        }

        if (!(arguments.get("search_term") instanceof String searchTerm) || searchTerm.isEmpty()) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent("search_term must be a nonempty string").build();
        }

        final int limit;
        final int offset;
        try {
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
            offset = QueryPageBounds.integer(arguments, "offset", 0, 0, Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent(e.getMessage()).build();
        }

        String searchLower = searchTerm.toLowerCase(Locale.ROOT);
        StringBuilder result = new StringBuilder();
        result.append("Functions matching \"").append(searchTerm).append("\":\n\n");

        int count = 0;
        long skipped = 0;
        boolean hasMore = false;
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (Thread.currentThread().isInterrupted()) {
                return McpSchema.CallToolResult.builder().isError(true).addTextContent("Function search interrupted").build();
            }
            if (func.getName(true).toLowerCase(Locale.ROOT).contains(searchLower)) {
                if (skipped++ < offset) continue;
                if (count == limit) { hasMore = true; break; }
                result.append("- ").append(func.getName(true))
                      .append(" @ ").append(func.getEntryPoint())
                      .append(" (").append(func.getParameterCount()).append(" params)\n");
                count++;
                rows.add(Map.of("name", func.getName(true), "address", func.getEntryPoint().toString(),
                    "parameter_count", func.getParameterCount()));
            }
        }

        if (count == 0) {
            result.append(offset == 0 ? "No functions found matching: " : "No further functions matching: ").append(searchTerm);
        } else {
            result.append("\nFound ").append(count).append(" matching functions");
        }

        if (hasMore) result.append("\nMore results available; next offset: ").append((long) offset + count);
        Map<String, Object> page = new LinkedHashMap<>();
        page.put("functions", rows);
        page.put("count", count);
        page.put("offset", offset);
        page.put("limit", limit);
        page.put("has_more", hasMore);
        page.put("next_offset", hasMore ? (long) offset + count : null);
        return QueryPageBounds.result(result.toString(), page);
    }
}
