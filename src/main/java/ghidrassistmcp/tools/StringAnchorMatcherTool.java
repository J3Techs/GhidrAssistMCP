/*
 * MCP tool that matches functions between programs by shared unique string references.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Matches functions between two open programs by finding shared unique string references.
 * A string that appears exactly once in each program and is referenced by exactly one
 * function in each provides a high-confidence function match.
 */
public class StringAnchorMatcherTool implements McpTool {

    @Override
    public String getName() {
        return "string_anchor_matcher";
    }

    @Override
    public String getDescription() {
        return "Match functions between two programs by shared unique string references. " +
               "Finds strings that exist in both programs and are referenced by exactly one function " +
               "in each, providing high-confidence function matches. " +
               "Returns matched function pairs with the anchor strings.";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "source_program", Map.of("type", "string", "description", "Name of the source program (with known symbols)"),
                "target_program", Map.of("type", "string", "description", "Name of the target program to match against"),
                "min_string_length", Map.of("type", "integer", "description", "Minimum string length to consider (default 6)", "default", 6),
                "limit", Map.of("type", "integer", "description", "Maximum number of matches to return (default 500)", "default", 500)
            ),
            List.of("source_program", "target_program"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        int minStringLength = 6;
        int limit = 500;

        if (arguments.get("min_string_length") instanceof Number)
            minStringLength = ((Number) arguments.get("min_string_length")).intValue();
        if (arguments.get("limit") instanceof Number)
            limit = ((Number) arguments.get("limit")).intValue();

        Program sourceProgram = findProgram(backend, sourceProgramName);
        Program targetProgram = findProgram(backend, targetProgramName);

        if (sourceProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Source program not found: " + sourceProgramName)
                .build();
        }
        if (targetProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Target program not found: " + targetProgramName)
                .build();
        }

        // Step 1: Build string-to-function map for source program
        Map<String, List<FuncRef>> sourceStringMap = buildStringFunctionMap(sourceProgram, minStringLength);

        // Step 2: Build string-to-function map for target program
        Map<String, List<FuncRef>> targetStringMap = buildStringFunctionMap(targetProgram, minStringLength);

        // Step 3: Find strings that are unique anchors in both programs
        List<StringMatch> matches = new ArrayList<>();

        for (Map.Entry<String, List<FuncRef>> entry : sourceStringMap.entrySet()) {
            String str = entry.getKey();
            List<FuncRef> sourceRefs = entry.getValue();

            // String must be referenced by exactly one function in source
            if (sourceRefs.size() != 1) continue;

            List<FuncRef> targetRefs = targetStringMap.get(str);
            if (targetRefs == null) continue;

            // String must be referenced by exactly one function in target
            if (targetRefs.size() != 1) continue;

            FuncRef sourceRef = sourceRefs.get(0);
            FuncRef targetRef = targetRefs.get(0);

            // Skip if source function is auto-named (not useful to transfer)
            if (sourceRef.funcName.startsWith("FUN_")) continue;

            // Skip if target already has same name (already matched)
            if (targetRef.funcName.equals(sourceRef.funcName)) continue;

            matches.add(new StringMatch(
                str, sourceRef.funcName, sourceRef.funcAddr,
                targetRef.funcName, targetRef.funcAddr));

            if (matches.size() >= limit) break;
        }

        // Sort by source function name for readability
        matches.sort((a, b) -> a.sourceFuncName.compareTo(b.sourceFuncName));

        // Format output
        StringBuilder result = new StringBuilder();
        result.append("String Anchor Match Results\n");
        result.append("==========================\n");
        result.append("Source: ").append(sourceProgramName).append("\n");
        result.append("Target: ").append(targetProgramName).append("\n");
        result.append("Unique strings in source: ").append(countUnique(sourceStringMap)).append("\n");
        result.append("Unique strings in target: ").append(countUnique(targetStringMap)).append("\n");
        result.append("Matched function pairs: ").append(matches.size()).append("\n\n");

        if (matches.isEmpty()) {
            result.append("No string-anchored matches found.");
        } else {
            // Output as JSON for easy consumption
            result.append("[\n");
            for (int i = 0; i < matches.size(); i++) {
                StringMatch m = matches.get(i);
                if (i > 0) result.append(",\n");
                result.append("  {");
                result.append("\"source_name\":").append(escapeJson(m.sourceFuncName));
                result.append(",\"source_addr\":\"").append(m.sourceFuncAddr).append("\"");
                result.append(",\"target_name\":").append(escapeJson(m.targetFuncName));
                result.append(",\"target_addr\":\"").append(m.targetFuncAddr).append("\"");
                result.append(",\"anchor_string\":").append(escapeJson(truncate(m.anchorString, 60)));
                result.append("}");
            }
            result.append("\n]");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Build a map of string value -> list of functions that reference that string.
     */
    private Map<String, List<FuncRef>> buildStringFunctionMap(Program program, int minLength) {
        Map<String, List<FuncRef>> stringMap = new HashMap<>();
        ReferenceManager refMgr = program.getReferenceManager();

        // Iterate all defined strings in the program
        var dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (!data.hasStringValue()) continue;

            String strValue = data.getDefaultValueRepresentation();
            if (strValue == null) continue;

            // Strip surrounding quotes if present
            if (strValue.startsWith("\"") && strValue.endsWith("\"") && strValue.length() > 2) {
                strValue = strValue.substring(1, strValue.length() - 1);
            }

            if (strValue.length() < minLength) continue;

            // Find functions that reference this string
            Address strAddr = data.getAddress();
            var refIter = refMgr.getReferencesTo(strAddr);

            Map<String, FuncRef> funcsSeen = new HashMap<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (func != null && !funcsSeen.containsKey(func.getName())) {
                    funcsSeen.put(func.getName(),
                        new FuncRef(func.getName(), func.getEntryPoint().toString()));
                }
            }

            if (!funcsSeen.isEmpty()) {
                stringMap.computeIfAbsent(strValue, k -> new ArrayList<>())
                    .addAll(funcsSeen.values());
            }
        }

        return stringMap;
    }

    private int countUnique(Map<String, List<FuncRef>> map) {
        int count = 0;
        for (List<FuncRef> refs : map.values()) {
            if (refs.size() == 1) count++;
        }
        return count;
    }

    private Program findProgram(GhidrAssistMCPBackend backend, String name) {
        for (Program p : backend.getAllOpenPrograms()) {
            if (p.getName().equals(name)) return p;
        }
        return null;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
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

    private static class FuncRef {
        String funcName;
        String funcAddr;
        FuncRef(String name, String addr) {
            this.funcName = name;
            this.funcAddr = addr;
        }
    }

    private static class StringMatch {
        String anchorString;
        String sourceFuncName;
        String sourceFuncAddr;
        String targetFuncName;
        String targetFuncAddr;

        StringMatch(String anchor, String srcName, String srcAddr, String tgtName, String tgtAddr) {
            this.anchorString = anchor;
            this.sourceFuncName = srcName;
            this.sourceFuncAddr = srcAddr;
            this.targetFuncName = tgtName;
            this.targetFuncAddr = tgtAddr;
        }
    }
}
