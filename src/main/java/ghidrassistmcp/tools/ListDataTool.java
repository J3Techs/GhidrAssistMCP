/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists defined data in the program.
 */
public class ListDataTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_data_vars";
    }
    
    @Override
    public String getDescription() {
        return "List defined data elements in the program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", QueryPageBounds.offsetSchema(),
                "limit", QueryPageBounds.limitSchema(),
                "data_type_filter", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        // Parse optional parameters
        final int offset;
        final int limit;
        try {
            offset = QueryPageBounds.integer(arguments, "offset", 0, 0, Integer.MAX_VALUE);
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
        String dataTypeFilter = (String) arguments.get("data_type_filter");
        
        BoundedQueryText result = new BoundedQueryText(BoundedQueryText.PAGE_CHARS - 1024);
        result.append("Defined Data Elements");
        if (dataTypeFilter != null) {
            result.append(" (filtered by: ").append(dataTypeFilter).append(")");
        }
        result.append(":\n\n");
        
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        
        int count = 0;
        int totalCount = 0;
        boolean rendering = true;
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            
            // Apply data type filter if specified
            if (dataTypeFilter != null) {
                DataType dataType = data.getDataType();
                if (dataType == null || !dataType.getName().toLowerCase().contains(dataTypeFilter.toLowerCase())) {
                    continue;
                }
            }
            
            totalCount++;
            
            // Apply offset
            if (totalCount <= offset) {
                continue;
            }
            
            // Apply limit to displayed results only; keep scanning for a true total.
            if (count < limit && rendering) {
                DataType dataType = data.getDataType();
                String typeName = dataType != null ? dataType.getName() : "unknown";
                String value = data.getDefaultValueRepresentation();
                if (value != null && value.length() > 50) {
                    value = value.substring(0, 47) + "...";
                }

                result.append("@ ").append(data.getAddress())
                      .append(" [").append(typeName).append("]");

                if (data.hasStringValue()) {
                    result.append(" String: ").append(value != null ? value : "null");
                } else if (value != null) {
                    result.append(" Value: ").append(value);
                }

                // Add symbol name if available
                if (data.getPrimarySymbol() != null) {
                    result.append(" (").append(data.getPrimarySymbol().getName()).append(")");
                }

                result.append("\n");
                count++;
                if (result.full()) { count--; rendering = false; }
            }
        }
        
        if (totalCount == 0) {
            if (dataTypeFilter != null) {
                result.append("No data elements found matching filter: ").append(dataTypeFilter);
            } else {
                result.append("No defined data elements found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" data elements");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        boolean hasMore = (long) offset + count < totalCount;
        String footer = "\nPage: offset=" + offset + ", limit=" + limit + ", has_more=" + hasMore
            + (hasMore ? ", next_offset=" + ((long) offset + count) : "")
            + (result.full() ? ", details_truncated=true; request the next page or narrower output" : "");
        return McpSchema.CallToolResult.builder().addTextContent(result.toString() + footer).build();
    }
}
