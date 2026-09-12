/*
 * MCP tool for getting cross-references to/from an address or function.
 * Consolidates xrefs_to, xrefs_from, and function_xrefs into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets cross-references to and/or from an address or function.
 * Replaces separate xrefs_to, xrefs_from, and function_xrefs tools.
 */
public class XrefsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "xrefs";
    }

    @Override
    public String getDescription() {
        return "Get cross-references to/from an address or function (direction: to, from, or both). " +
               "Supports call graph traversal with depth parameter for function-based queries.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("address", Map.of(
                    "type", "string",
                    "description", "Optional: address to find xrefs for (either address or function must be provided)"
                )),
                Map.entry("function", Map.of(
                    "type", "string",
                    "description", "Optional: function name to find callers/callees xrefs for (either address or function must be provided)"
                )),
                Map.entry("direction", Map.of(
                    "type", "string",
                    "description", "Direction of cross-references to return",
                    "enum", List.of("to", "from", "both"),
                    "default", "both"
                )),
                Map.entry("include_calls", Map.of(
                    "type", "boolean",
                    "description", "Optional: if true and function is specified, include recursive call graph (default false)",
                    "default", false
                )),
                Map.entry("depth", Map.of(
                    "type", "integer",
                    "minimum", 0, "maximum", 5,
                    "description", "Optional: max call graph depth when include_calls is true (default 2, max 5)",
                    "default", 2
                )),
                Map.entry("limit", Map.of(
                    "type", "integer",
                    "minimum", 1, "maximum", QueryPageBounds.MAX_LIMIT,
                    "description", "Maximum references per direction; aggregate row budget for call graphs (default 100, max 1000)"
                ))
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No program currently loaded")
                .build();
        }

        String addressStr = (String) arguments.get("address");
        String functionName = (String) arguments.get("function");
        String direction = (String) arguments.get("direction");
        final int limit;
        final int depth;
        try {
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
            depth = QueryPageBounds.integer(arguments, "depth", 2, 0, 5);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }

        if (direction == null || direction.isEmpty()) {
            direction = "both";
        }
        direction = direction.toLowerCase();

        if (!direction.equals("to") && !direction.equals("from") && !direction.equals("both")) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Invalid direction. Use 'to', 'from', or 'both'")
                .build();
        }

        // Check that at least one of address or function is provided
        if ((addressStr == null || addressStr.isEmpty()) && (functionName == null || functionName.isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Either 'address' or 'function' parameter is required")
                .build();
        }

        // Check for call graph mode
        boolean includeCalls = false;
        if (arguments.get("include_calls") instanceof Boolean) {
            includeCalls = (Boolean) arguments.get("include_calls");
        }

        // If function is provided, use function-based xrefs
        if (functionName != null && !functionName.isEmpty()) {
            if (includeCalls) {
                return getCallGraph(currentProgram, functionName, direction, depth, limit);
            }
            return getFunctionXrefs(currentProgram, functionName, direction, limit);
        }

        // Otherwise, use address-based xrefs
        return getAddressXrefs(currentProgram, addressStr, direction, limit);
    }

    /**
     * Get cross-references for an address.
     */
    private McpSchema.CallToolResult getAddressXrefs(Program program, String addressStr, String direction, int limit) {
        // Parse the address
        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .isError(true).addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Error parsing address: " + e.getMessage())
                .build();
        }

        BoundedQueryText result = new BoundedQueryText();
        result.append("Cross-references for ").append(addressStr).append(":\n\n");

        // Get references TO this address
        if (direction.equals("to") || direction.equals("both")) {
            result.append("## References TO this address:\n");
            ReferenceIterator refsTo = program.getReferenceManager().getReferencesTo(address);
            int count = 0;

            while (refsTo.hasNext() && count < limit && !result.full()) {
                Reference ref = refsTo.next();
                result.append("  - From: ").append(ref.getFromAddress())
                      .append(" (").append(ref.getReferenceType()).append(")\n");
                count++;
            }

            if (count == 0) {
                result.append("  No references found.\n");
            } else if (refsTo.hasNext() || result.full()) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
            result.append("\n");
        }

        // Get references FROM this address
        if (direction.equals("from") || direction.equals("both")) {
            result.append("## References FROM this address:\n");
            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(address);
            int count = 0;

            for (Reference ref : refsFrom) {
                if (count >= limit || result.full()) break;
                result.append("  - To: ").append(ref.getToAddress())
                      .append(" (").append(ref.getReferenceType()).append(")\n");
                count++;
            }

            if (count == 0) {
                result.append("  No references found.\n");
            } else if (count < refsFrom.length || result.full()) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Get cross-references for a function (callers and callees).
     */
    private McpSchema.CallToolResult getFunctionXrefs(Program program, String functionName, String direction, int limit) {
        // Find the function
        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Function not found: " + functionName)
                .build();
        }

        BoundedQueryText result = new BoundedQueryText();
        result.append("Cross-references for function: ").append(functionName).append("\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\n\n");

        int totalCount = 0;
        int count = 0;

        // Get XREFs TO the function (callers)
        if (direction.equals("to") || direction.equals("both")) {
            result.append("## References TO function (callers):\n");
            Set<Function> callingFunctions = function.getCallingFunctions(TaskMonitor.DUMMY);

            for (Function callerFunc : callingFunctions) {
                if (count >= limit || result.full()) {
                    break;
                }

                result.append("  - ").append(callerFunc.getEntryPoint())
                      .append(" (").append(callerFunc.getName()).append(")\n");
                count++;
                totalCount++;
            }

            if (callingFunctions.isEmpty()) {
                result.append("  No callers found.\n");
            } else if (count < callingFunctions.size() || result.full()) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
            result.append("\n");
        }

        // Get XREFs FROM the function (callees)
        if (direction.equals("from") || direction.equals("both")) {
            result.append("## References FROM function (callees):\n");
            Set<Function> calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);

            int calleeCount = 0;
            for (Function calledFunc : calledFunctions) {
                if (calleeCount >= limit || result.full()) {
                    break;
                }

                result.append("  - ").append(calledFunc.getEntryPoint())
                      .append(" (").append(calledFunc.getName()).append(")\n");
                calleeCount++;
                totalCount++;
            }

            if (calledFunctions.isEmpty()) {
                result.append("  No called functions found.\n");
            } else if (calleeCount < calledFunctions.size() || result.full()) {
                result.append("  ... (limited to ").append(limit).append(" results)\n");
            }
        }

        if (totalCount == 0) {
            result.append("No cross-references found for function: ").append(functionName);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Get call graph for a function with recursive depth traversal.
     * Absorbs functionality from the former GetCallGraphTool.
     */
    private McpSchema.CallToolResult getCallGraph(Program program, String functionName, String direction, int depth, int limit) {
        Function function = FunctionLookup.resolve(program, functionName);
        if (function == null) return ProjectToolSupport.error("Function not found: " + functionName);
        return McpSchema.CallToolResult.builder().addTextContent(GetCallGraphTool.render(function, depth,
            direction.equals("to") ? "callers" : direction.equals("from") ? "callees" : "both", limit)).build();
    }

    /**
     * Find a function by name.
     */
    private Function findFunctionByName(Program program, String functionName) {
        return FunctionLookup.resolve(program, functionName);
    }
}
