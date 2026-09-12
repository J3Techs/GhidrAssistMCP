/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists imported functions and symbols.
 */
public class ListImportsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_imports";
    }
    
    @Override
    public String getDescription() {
        return "List imported functions and symbols";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "structured", Map.of("type", "boolean", "default", false),
                "library", Map.of("type", "string", "description", "Exact external library filter for structured output"),
                "reference_limit", Map.of("type", "integer", "default", 100, "maximum", 1000)
            ),
            List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (Boolean.TRUE.equals(arguments.get("structured"))) return structured(arguments, currentProgram);
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        // Parse optional offset and limit
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Imported Functions and Symbols:\n\n");
        
        SymbolIterator symbolIter = currentProgram.getSymbolTable().getSymbolIterator();
        
        int count = 0;
        int totalCount = 0;
        
        while (symbolIter.hasNext()) {
            Symbol symbol = symbolIter.next();
            
            // Only include external symbols (imports)
            if (symbol.isExternal() && 
                (symbol.getSymbolType() == SymbolType.FUNCTION || 
                 symbol.getSymbolType() == SymbolType.LABEL)) {
                
                totalCount++;
                
                // Apply offset
                if (totalCount <= offset) {
                    continue;
                }
                
                // Apply limit to displayed results only; keep scanning for a true total.
                if (count < limit) {
                    String libraryName = "unknown";
                    if (symbol.getParentNamespace() != null) {
                        libraryName = symbol.getParentNamespace().getName();
                    }

                    result.append("- ").append(symbol.getName())
                          .append(" from ").append(libraryName)
                          .append(" @ ").append(symbol.getAddress())
                          .append(" (").append(symbol.getSymbolType()).append(")")
                          .append("\n");

                    count++;
                }
            }
        }
        
        if (totalCount == 0) {
            result.append("No imported symbols found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" imports");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private McpSchema.CallToolResult structured(Map<String, Object> args, Program program) {
        try {
            if (program == null) return ProjectToolSupport.error("No program currently loaded");
            int offset = BatchQuerySupport.integer(args, "offset", 0, 100000);
            int limit = BatchQuerySupport.integer(args, "limit", 100, 1000);
            int referenceLimit = BatchQuerySupport.integer(args, "reference_limit", 100, 1000);
            if ((long) limit * referenceLimit > 100000) throw new IllegalArgumentException("Reduce limit/reference_limit; total reference budget is 100000");
            String library = args.containsKey("library") ? BatchQuerySupport.text(args.get("library"), "library") : null;
            var rows = new java.util.ArrayList<Map<String, Object>>();
            SymbolIterator iterator = program.getSymbolTable().getExternalSymbols();
            int matched = 0, scanned = 0;
            while (iterator.hasNext() && scanned < 100000) {
                Symbol symbol = iterator.next(); scanned++;
                var location = program.getExternalManager().getExternalLocation(symbol);
                if (location == null || library != null && !library.equals(location.getLibraryName())) continue;
                if (matched++ < offset) continue;
                if (rows.size() >= limit) break;
                var row = new java.util.LinkedHashMap<String, Object>(BatchQuerySupport.symbol(symbol));
                row.put("id", Long.toString(symbol.getID())); row.put("library", location.getLibraryName());
                row.put("namespace", symbol.getParentNamespace().getName(true));
                row.put("original_name", java.util.Objects.toString(location.getOriginalImportedName(), ""));
                row.put("library_path", java.util.Objects.toString(program.getExternalManager().getExternalLibraryPath(location.getLibraryName()), ""));
                if (location.getAddress() != null) row.put("original_address", BatchQuerySupport.addr(location.getAddress()));
                var refs = program.getReferenceManager().getReferencesTo(symbol.getAddress());
                var callers = new java.util.ArrayList<Map<String, Object>>();
                while (refs.hasNext() && callers.size() < referenceLimit) {
                    var ref = refs.next(); var edge = new java.util.LinkedHashMap<String, Object>(BatchQuerySupport.addr(ref.getFromAddress()));
                    edge.put("type", ref.getReferenceType().toString()); edge.put("operand_index", ref.getOperandIndex());
                    var function = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (function != null) edge.put("function", BatchQuerySupport.function(function));
                    callers.add(edge);
                }
                row.put("references", callers); row.put("references_truncated", refs.hasNext());
                rows.add(row);
            }
            boolean more = matched > offset + rows.size() || iterator.hasNext();
            return ProjectToolSupport.result(Map.of("program", ghidrassistmcp.ProgramIdentity.describe(program),
                "imports", rows, "count", rows.size(), "offset", offset, "next_offset", offset + rows.size(),
                "truncated", more, "scanned", scanned));
        } catch (Exception e) { return ProjectToolSupport.error(e.getMessage()); }
    }
}
