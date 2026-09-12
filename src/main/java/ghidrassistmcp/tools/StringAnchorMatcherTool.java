/*
 * MCP tool that matches functions between programs by shared unique string references.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Matches functions between two open programs by shared string references.
 * A string is a unique anchor only when it occurs once and is referenced by
 * exactly one function on each side. Duplicate string data items are counted
 * as separate occurrences and cannot claim uniqueness.
 */
public class StringAnchorMatcherTool implements McpTool {

    @Override
    public String getName() {
        return "string_anchor_matcher";
    }

    @Override
    public String getDescription() {
        return "Match functions between two programs by shared string references. "
            + "A 1-function reference is not uniqueness if the string value appears more than once. "
            + "Returns structured JSON with full anchor text plus a separate preview; a result cap "
            + "or truncated scan cannot establish uniqueness.";
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
                "source_program", Map.of("type", "string", "description", "Exact source name, project path, URL or program_id; ambiguous names fail"),
                "target_program", Map.of("type", "string", "description", "Exact target name, project path, URL or program_id; ambiguous names fail"),
                "min_string_length", Map.of("type", "integer", "minimum", 1, "maximum", 65536,
                    "description", "Minimum string length to consider (default 6)", "default", 6),
                "limit", Map.of("type", "integer", "minimum", 1, "maximum", QueryPageBounds.MAX_LIMIT,
                    "description", "Maximum number of matches to return (default 500)", "default", 500)
            ),
            List.of("source_program", "target_program"), null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        Map<String, Object> programRef = MatcherContracts.objectSchema(props(
            "program_id", Map.of("type", "string"),
            "name", Map.of("type", "string"),
            "modification_number", Map.of("type", "string"),
            "language", Map.of("type", "string"),
            "processor", Map.of("type", "string")
        ), List.of("program_id", "name", "modification_number"));
        Map<String, Object> match = MatcherContracts.objectSchema(props(
            "source_name", Map.of("type", "string"),
            "source_addr", Map.of("type", "string"),
            "target_name", Map.of("type", "string"),
            "target_addr", Map.of("type", "string"),
            "anchor_string", Map.of("type", "string"),
            "anchor_preview", Map.of("type", "string"),
            "anchor_truncated", Map.of("type", "boolean"),
            "anchor_length", Map.of("type", "integer", "minimum", 0),
            "source_occurrence_count", Map.of("type", "integer", "minimum", 0),
            "target_occurrence_count", Map.of("type", "integer", "minimum", 0),
            "source_function_ref_count", Map.of("type", "integer", "minimum", 0),
            "target_function_ref_count", Map.of("type", "integer", "minimum", 0),
            "unique_anchor", Map.of("type", "boolean"),
            "names_already_equal", Map.of("type", "boolean")
        ), List.of("source_name", "source_addr", "target_name", "target_addr",
            "anchor_string", "anchor_preview", "anchor_truncated", "unique_anchor"));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("source_program", programRef);
        properties.put("target_program", programRef);
        properties.put("min_string_length", Map.of("type", "integer"));
        properties.put("limit", Map.of("type", "integer"));
        properties.put("source_string_count", Map.of("type", "integer", "minimum", 0));
        properties.put("target_string_count", Map.of("type", "integer", "minimum", 0));
        properties.put("unique_anchor_count", Map.of("type", "integer", "minimum", 0));
        properties.put("candidate_count", Map.of("type", "integer", "minimum", 0));
        properties.put("result_cap", Map.of("type", "integer", "minimum", 1));
        properties.put("scan_complete", Map.of("type", "boolean"));
        properties.put("scan_truncated", Map.of("type", "boolean"));
        properties.put("cancelled", Map.of("type", "boolean"));
        properties.put("unique", Map.of("type", "boolean"));
        properties.put("matches", Map.of("type", "array", "items", match, "maxItems", QueryPageBounds.MAX_LIMIT));
        return MatcherContracts.objectSchema(properties, List.of(
            "source_program", "target_program", "candidate_count", "result_cap",
            "scan_complete", "scan_truncated", "cancelled", "unique", "matches"));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder().isError(true)
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        return execute(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, McpTask task) {
        if (backend == null) {
            return ProjectToolSupport.error("Backend context not available");
        }

        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        final int minStringLength;
        final int limit;
        try {
            minStringLength = QueryPageBounds.integer(arguments, "min_string_length", 6, 1, 65536);
            limit = QueryPageBounds.integer(arguments, "limit", 500, 1, QueryPageBounds.MAX_LIMIT);
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        }

        TaskMonitor monitor = task == null ? TaskMonitor.DUMMY : new McpTaskMonitor(task, 0, 100, "String anchor matcher");

        try (var sourceLease = ProgramSelection.lease(backend, sourceProgramName, currentProgram);
             var targetLease = ProgramSelection.lease(backend, targetProgramName, currentProgram)) {
            Program sourceProgram = sourceLease.program();
            Program targetProgram = targetLease.program();

            IndexOutcome sourceIndex = buildStringFunctionMap(sourceProgram, minStringLength, monitor);
            IndexOutcome targetIndex = buildStringFunctionMap(targetProgram, minStringLength, monitor);
            boolean cancelled = sourceIndex.cancelled || targetIndex.cancelled;

            List<Map<String, Object>> matches = new ArrayList<>();
            int uniqueAnchorCount = 0;

            for (Map.Entry<String, StringStats> entry : sourceIndex.stats.entrySet()) {
                if (cancelled) break;
                String str = entry.getKey();
                StringStats sourceStats = entry.getValue();
                StringStats targetStats = targetIndex.stats.get(str);
                if (targetStats == null) continue;
                if (sourceStats.functions.size() != 1 || targetStats.functions.size() != 1) continue;

                boolean unique = MatcherContracts.uniqueAnchor(sourceStats.occurrences, sourceStats.functions.size())
                    && MatcherContracts.uniqueAnchor(targetStats.occurrences, targetStats.functions.size());
                if (unique) uniqueAnchorCount++;

                FuncRef sourceRef = sourceStats.functions.values().iterator().next();
                FuncRef targetRef = targetStats.functions.values().iterator().next();
                Map<String, Object> row = new LinkedHashMap<>(MatcherContracts.anchorFields(str, MatcherContracts.DEFAULT_ANCHOR_PREVIEW));
                row.put("source_name", sourceRef.funcName);
                row.put("source_addr", sourceRef.funcAddr);
                row.put("target_name", targetRef.funcName);
                row.put("target_addr", targetRef.funcAddr);
                row.put("source_occurrence_count", sourceStats.occurrences);
                row.put("target_occurrence_count", targetStats.occurrences);
                row.put("source_function_ref_count", sourceStats.functions.size());
                row.put("target_function_ref_count", targetStats.functions.size());
                row.put("unique_anchor", unique);
                row.put("names_already_equal", sourceRef.funcName.equals(targetRef.funcName));
                matches.add(row);
            }

            matches.sort((a, b) -> {
                int uniqueCmp = Boolean.compare((Boolean) b.get("unique_anchor"), (Boolean) a.get("unique_anchor"));
                if (uniqueCmp != 0) return uniqueCmp;
                return ((String) a.get("source_name")).compareTo((String) b.get("source_name"));
            });
            boolean moreExist = matches.size() > limit;
            if (moreExist) matches = new ArrayList<>(matches.subList(0, limit));

            MatcherContracts.ScanStatus status = MatcherContracts.scanStatus(
                matches.size(), limit, moreExist, cancelled, !cancelled);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("source_program", MatcherContracts.programRef(sourceProgram));
            body.put("target_program", MatcherContracts.programRef(targetProgram));
            body.put("min_string_length", minStringLength);
            body.put("limit", limit);
            body.put("source_string_count", sourceIndex.stats.size());
            body.put("target_string_count", targetIndex.stats.size());
            body.put("unique_anchor_count", uniqueAnchorCount);
            body.putAll(MatcherContracts.scanFields(status));
            body.put("matches", matches);

            String summary = "String anchor match: " + matches.size() + " candidate(s), unique_anchor_count="
                + uniqueAnchorCount + ", scan_complete=" + status.scanComplete()
                + ", scan_truncated=" + status.scanTruncated() + ".";
            return QueryPageBounds.result(summary, body);
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        }
    }

    private IndexOutcome buildStringFunctionMap(Program program, int minLength, TaskMonitor monitor) {
        IndexOutcome outcome = new IndexOutcome();
        ReferenceManager refMgr = program.getReferenceManager();
        var dataIter = program.getListing().getDefinedData(true);
        try {
            while (dataIter.hasNext()) {
                monitor.checkCancelled();
                Data data = dataIter.next();
                if (!data.hasStringValue()) continue;
                String strValue = stringValue(data);
                if (strValue == null || strValue.length() < minLength) continue;

                Address strAddr = data.getAddress();
                StringStats stats = outcome.stats.computeIfAbsent(strValue, k -> new StringStats());
                stats.occurrences++;

                var refIter = refMgr.getReferencesTo(strAddr);
                while (refIter.hasNext()) {
                    monitor.checkCancelled();
                    Reference ref = refIter.next();
                    Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (func == null) continue;
                    String entry = func.getEntryPoint().toString();
                    stats.functions.putIfAbsent(entry, new FuncRef(func.getName(true), entry));
                }
            }
        } catch (CancelledException e) {
            outcome.cancelled = true;
        }
        return outcome;
    }

    private static String stringValue(Data data) {
        Object value = data.getValue();
        if (value instanceof String s) return s;
        String repr = data.getDefaultValueRepresentation();
        if (repr == null) return null;
        if (repr.length() >= 2 && repr.startsWith("\"") && repr.endsWith("\"")) {
            return repr.substring(1, repr.length() - 1);
        }
        return repr;
    }

    private static Map<String, Object> props(Object... entries) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put((String) entries[i], entries[i + 1]);
        return result;
    }

    private static final class IndexOutcome {
        final Map<String, StringStats> stats = new LinkedHashMap<>();
        boolean cancelled;
    }

    private static final class StringStats {
        int occurrences;
        final Map<String, FuncRef> functions = new LinkedHashMap<>();
    }

    private static final class FuncRef {
        final String funcName;
        final String funcAddr;
        FuncRef(String name, String addr) {
            this.funcName = name;
            this.funcAddr = addr;
        }
    }
}
