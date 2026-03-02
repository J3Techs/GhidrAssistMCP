/*
 * MCP tool that exports function signatures from a program as JSON for cross-binary matching.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Exports named function signatures from a program as JSON. Includes name, address,
 * size, entry bytes (hex), prototype, and string references. Used to build a reference
 * set from a fully-analyzed binary (e.g. ELF with symbols) for matching against
 * a stripped binary.
 */
public class ExportFunctionSignaturesTool implements McpTool {

    @Override
    public String getName() {
        return "export_function_signatures";
    }

    @Override
    public String getDescription() {
        return "Export named function signatures as JSON for cross-binary matching. " +
               "Returns name, address, size, entry bytes, prototype, and string references. " +
               "Use 'skip_unnamed' (default true) to exclude auto-named FUN_ functions. " +
               "Supports pagination with offset/limit.";
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "offset", Map.of("type", "integer", "description", "Skip first N functions (default 0)", "default", 0),
                "limit", Map.of("type", "integer", "description", "Max functions to export (default 200)", "default", 200),
                "entry_bytes_count", Map.of("type", "integer", "description", "Number of entry bytes to capture per function (default 32)", "default", 32),
                "skip_unnamed", Map.of("type", "boolean", "description", "Skip auto-named FUN_/thunk_ functions (default true)", "default", true),
                "pattern", Map.of("type", "string", "description", "Optional: filter function names by substring match")
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

        int offset = 0;
        int limit = 200;
        int entryBytesCount = 32;
        boolean skipUnnamed = true;
        String pattern = null;

        if (arguments.get("offset") instanceof Number)
            offset = ((Number) arguments.get("offset")).intValue();
        if (arguments.get("limit") instanceof Number)
            limit = ((Number) arguments.get("limit")).intValue();
        if (arguments.get("entry_bytes_count") instanceof Number)
            entryBytesCount = ((Number) arguments.get("entry_bytes_count")).intValue();
        if (arguments.get("skip_unnamed") instanceof Boolean)
            skipUnnamed = (Boolean) arguments.get("skip_unnamed");
        if (arguments.get("pattern") instanceof String)
            pattern = (String) arguments.get("pattern");

        Memory memory = currentProgram.getMemory();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        StringBuilder json = new StringBuilder();
        json.append("[\n");

        int skipped = 0;
        int exported = 0;
        int totalMatched = 0;

        while (functions.hasNext()) {
            Function func = functions.next();
            String name = func.getName();

            // Skip auto-named functions
            if (skipUnnamed && (name.startsWith("FUN_") || name.startsWith("thunk_"))) {
                continue;
            }

            // Apply pattern filter
            if (pattern != null && !name.toLowerCase().contains(pattern.toLowerCase())) {
                continue;
            }

            totalMatched++;

            // Apply offset
            if (skipped < offset) {
                skipped++;
                continue;
            }

            // Apply limit
            if (exported >= limit) {
                continue; // keep counting totalMatched
            }

            if (exported > 0) {
                json.append(",\n");
            }

            Address entry = func.getEntryPoint();
            long bodySize = func.getBody().getNumAddresses();

            // Read entry bytes
            String entryHex = readBytesHex(memory, entry, Math.min(entryBytesCount, (int) bodySize));

            // Get prototype
            String prototype = func.getSignature().getPrototypeString(false);

            // Collect string references from this function
            StringBuilder strRefs = new StringBuilder();
            strRefs.append("[");
            int strCount = 0;
            ReferenceIterator refIter = currentProgram.getReferenceManager()
                .getReferenceIterator(func.getBody().getMinAddress());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                if (!func.getBody().contains(fromAddr)) {
                    if (fromAddr.compareTo(func.getBody().getMaxAddress()) > 0) break;
                    continue;
                }
                Address toAddr = ref.getToAddress();
                Data data = currentProgram.getListing().getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    String strVal = data.getDefaultValueRepresentation();
                    if (strVal != null && strVal.length() > 2) {
                        if (strCount > 0) strRefs.append(",");
                        strRefs.append(escapeJson(strVal));
                        strCount++;
                        if (strCount >= 10) break; // cap string refs per function
                    }
                }
            }
            strRefs.append("]");

            json.append("  {");
            json.append("\"name\":").append(escapeJson(name));
            json.append(",\"address\":\"").append(entry).append("\"");
            json.append(",\"size\":").append(bodySize);
            json.append(",\"entry_bytes\":\"").append(entryHex).append("\"");
            json.append(",\"prototype\":").append(escapeJson(prototype));
            json.append(",\"string_refs\":").append(strRefs);
            json.append("}");

            exported++;
        }

        json.append("\n]");

        StringBuilder result = new StringBuilder();
        result.append("Exported ").append(exported).append(" of ").append(totalMatched)
              .append(" named functions");
        if (offset > 0) result.append(" (offset: ").append(offset).append(")");
        result.append("\n\n");
        result.append(json);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private String readBytesHex(Memory memory, Address addr, int count) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < count; i++) {
            try {
                byte b = memory.getByte(addr.add(i));
                hex.append(String.format("%02x", b & 0xFF));
            } catch (MemoryAccessException e) {
                hex.append("??");
            }
        }
        return hex.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
