package ghidrassistmcp.tools;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/** Bounded call graph shared by the legacy graph and xrefs entry points. */
public class GetCallGraphTool implements McpTool {
    @Override public boolean isCacheable() { return true; }
    @Override public String getName() { return "get_call_graph"; }
    @Override public String getDescription() {
        return "Get callers/callees with depth 0-5 and an aggregate max_nodes output budget across both directions. "
            + "Truncation is explicit; narrow direction/depth or choose another root to inspect remaining edges.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "function", Map.of("type", "string", "description", "Function address, containing address, or qualified name"),
            "depth", Map.of("type", "integer", "minimum", 0, "maximum", 5, "default", 2),
            "max_nodes", Map.of("type", "integer", "minimum", 1, "maximum", 10000, "default", 1000,
                "description", "Maximum emitted node/edge rows in the whole response, including repeated nodes"),
            "direction", Map.of("type", "string", "enum", List.of("both", "callers", "callees"), "default", "both")),
            List.of("function"), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        try {
            int depth = QueryPageBounds.integer(arguments, "depth", 2, 0, 5);
            int maximum = QueryPageBounds.integer(arguments, "max_nodes", 1000, 1, 10000);
            String direction = arguments.getOrDefault("direction", "both") instanceof String value ? value : "";
            if (!List.of("both", "callers", "callees").contains(direction))
                return ProjectToolSupport.error("Invalid direction. Use 'both', 'callers', or 'callees'");
            String identifier = arguments.get("function") instanceof String value ? value : null;
            Function function = FunctionLookup.resolve(program, identifier);
            if (function == null) return ProjectToolSupport.error("Function not found: " + identifier);
            return McpSchema.CallToolResult.builder().addTextContent(render(function, depth, direction, maximum)).build();
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
    }
    static String render(Function function, int depth, String direction, int maximum) {
        var budget = new Budget(maximum);
        budget.text.append("Call Graph for: ").append(function.getName(true)).append(" @ ")
            .append(function.getEntryPoint()).append("\n\n");
        if (!direction.equals("callees")) {
            budget.text.append("## Calling Functions (Who calls this):\n");
            visit(function, depth, 0, true, new HashSet<>(), budget);
            budget.text.append("\n");
        }
        if (!direction.equals("callers")) {
            budget.text.append("## Called Functions (What this calls):\n");
            visit(function, depth, 0, false, new HashSet<>(), budget);
        }
        return budget.text.toString();
    }
    private static void visit(Function function, int maxDepth, int depth, boolean callers, Set<String> visited, Budget budget) {
        if (Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("Graph query cancelled");
        if (budget.rows == budget.maximum || budget.text.full()) { budget.text.truncate(); return; }
        budget.rows++;
        String key = function.getEntryPoint().toString();
        boolean first = visited.add(key);
        budget.text.append("  ".repeat(depth)).append("- ").append(function.getName(true))
            .append(" @ ").append(function.getEntryPoint())
            .append(first ? "\n" : " (recursive/already visited)\n");
        if (!first || depth == maxDepth || budget.text.full()) return;
        Set<Function> adjacent = callers ? function.getCallingFunctions(TaskMonitor.DUMMY) : function.getCalledFunctions(TaskMonitor.DUMMY);
        for (Function next : adjacent) {
            if (budget.rows == budget.maximum || budget.text.full()) { budget.text.truncate(); break; }
            visit(next, maxDepth, depth + 1, callers, visited, budget);
        }
    }
    private static final class Budget {
        final BoundedQueryText text = new BoundedQueryText();
        final int maximum;
        int rows;
        Budget(int maximum) { this.maximum = maximum; }
    }
}
