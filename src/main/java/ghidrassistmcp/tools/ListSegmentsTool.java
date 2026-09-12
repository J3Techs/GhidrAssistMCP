/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists memory segments/blocks in the program.
 */
public class ListSegmentsTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_segments";
    }
    
    @Override
    public String getDescription() {
        return "List memory segments/blocks in the program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", QueryPageBounds.offsetSchema(),
                "limit", QueryPageBounds.limitSchema()
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
        
        // Parse optional offset and limit
        final int offset;
        final int limit;
        try {
            offset = QueryPageBounds.integer(arguments, "offset", 0, 0, Integer.MAX_VALUE);
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
        
        BoundedQueryText result = new BoundedQueryText(BoundedQueryText.PAGE_CHARS - 1024);
        result.append("Memory Segments/Blocks:\n\n");
        
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        
        int count = 0;
        int totalCount = blocks.length;
        boolean rendering = true;
        
        for (int i = offset; i < blocks.length && count < limit; i++) {
            MemoryBlock block = blocks[i];
            if (!rendering) continue;
            
            String permissions = "";
            if (block.isRead()) permissions += "R";
            if (block.isWrite()) permissions += "W";
            if (block.isExecute()) permissions += "X";
            
            result.append("- ").append(block.getName())
                  .append(" @ ").append(block.getStart())
                  .append("-").append(block.getEnd())
                  .append(" (").append(String.format("0x%x", block.getSize())).append(" bytes)")
                  .append(" [").append(permissions).append("]")
                  .append(" Type: ").append(block.getType())
                  .append("\n");
            
            count++;
            if (result.full()) { count--; rendering = false; }
        }
        
        if (totalCount == 0) {
            result.append("No memory blocks found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" segments");
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
