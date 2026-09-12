/*
 * MCP tool for getting basic blocks (control flow graph).
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets basic blocks and control flow graph for a function.
 */
public class GetBasicBlocksTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_basic_blocks";
    }

    @Override
    public String getDescription() {
        return "Get basic blocks and control flow graph for a function";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function", new McpSchema.JsonSchema("string", null, null, null, null, null)
                , "offset", QueryPageBounds.offsetSchema(), "limit", QueryPageBounds.limitSchema()
            ),
            List.of("function"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String functionIdentifier = (String) arguments.get("function");
        final int offset, limit;
        try {
            offset = QueryPageBounds.integer(arguments, "offset", 0, 0, Integer.MAX_VALUE);
            limit = QueryPageBounds.integer(arguments, "limit", 100, 1, QueryPageBounds.MAX_LIMIT);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionIdentifier)
                .build();
        }

        BoundedQueryText result = new BoundedQueryText(BoundedQueryText.PAGE_CHARS - 1024);
        String pageSummary = "";
        result.append("Basic Blocks for: ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        try {
            BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(
                function.getBody(), TaskMonitor.DUMMY);

            int blockCount = 0;
            int matched = 0;
            boolean hasMore = false;
            boolean edgesTruncated = false;

            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                if (matched++ < offset) continue;
                if (blockCount >= limit) { hasMore = true; break; }
                blockCount++;

                result.append("## Block ").append(blockCount).append("\n");
                result.append("- **Start**: ").append(block.getFirstStartAddress()).append("\n");
                result.append("- **End**: ").append(block.getMaxAddress()).append("\n");
                result.append("- **Size**: ").append(block.getNumAddresses()).append(" addresses\n");
                result.append("- **Name**: ").append(block.getName()).append("\n");

                // Get successors (where control can flow to)
                result.append("- **Successors**:\n");
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                boolean hasSucc = false;
                int edgeCount = 0;
                while (destIter.hasNext()) {
                    if (++edgeCount > 256) { edgesTruncated = true; result.append("    - (edge output truncated at 256)\n"); break; }
                    CodeBlockReference ref = destIter.next();
                    result.append("    - ").append(ref.getDestinationAddress())
                          .append(" (").append(ref.getFlowType()).append(")\n");
                    hasSucc = true;
                }
                if (!hasSucc) {
                    result.append("    - (none - exit block)\n");
                }

                // Get predecessors (where control can come from)
                result.append("- **Predecessors**:\n");
                CodeBlockReferenceIterator srcIter = block.getSources(TaskMonitor.DUMMY);
                boolean hasPred = false;
                edgeCount = 0;
                while (srcIter.hasNext()) {
                    if (++edgeCount > 256) { edgesTruncated = true; result.append("    - (edge output truncated at 256)\n"); break; }
                    CodeBlockReference ref = srcIter.next();
                    result.append("    - ").append(ref.getSourceAddress())
                          .append(" (").append(ref.getFlowType()).append(")\n");
                    hasPred = true;
                }
                if (!hasPred) {
                    result.append("    - (none - entry block)\n");
                }

                result.append("\n");
                if (result.full()) { hasMore = blocks.hasNext(); break; }
            }

            result.append("## Summary\n");
            result.append("- Total Basic Blocks: ").append(blockCount).append("\n");
            result.append("- Function Size: ").append(function.getBody().getNumAddresses()).append(" addresses\n");
            // Keep continuation outside the bounded builder so truncation cannot suppress it.
            pageSummary = "\nPage: offset=" + offset + ", limit=" + limit + ", returned_blocks=" + blockCount
                + ", has_more=" + hasMore + ", details_truncated=" + (result.full() || edgesTruncated);
            if (hasMore) pageSummary += ", next_offset=" + ((long) offset + blockCount);
            if (result.full()) pageSummary += ", partial_block_offset=" + ((long) offset + Math.max(0, blockCount - 1));
            if (edgesTruncated) pageSummary += "\nEdge lists are capped at 256 per direction; this page does not enumerate all edges.";

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error getting basic blocks: " + e.getMessage())
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString() + pageSummary)
            .build();
    }

    private Function findFunction(Program program, String identifier) {
        return FunctionLookup.resolve(program, identifier);
    }
}
