package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/** Bounded, architecture-neutral instruction text scan. */
public class ScanInstructionsTool implements McpTool {
    private static final int DEFAULT_LIMIT = 1000, MAX_LIMIT = 100000;
    @Override public String getName() { return "scan_instructions"; }
    @Override public String getDescription() {
        return "Scan bounded address ranges for instruction mnemonic and operand-text predicates.";
    }
    @Override public boolean isReadOnly() { return true; }
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean isCacheable() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "ranges", Map.of("type", "string", "description", "Comma-separated half-open [start,end) ranges"),
            "mnemonics", Map.of("type", "array", "items", Map.of("type", "string")),
            "operand_contains", Map.of("type", "string"),
            "max_instructions", Map.of("type", "integer", "default", DEFAULT_LIMIT),
            "include_bytes", Map.of("type", "boolean", "default", false)
        ), List.of("ranges"), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return scan(args, program, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
                                                       ghidrassistmcp.GhidrAssistMCPBackend backend, McpTask task) {
        return scan(args, program, task);
    }
    private McpSchema.CallToolResult scan(Map<String, Object> args, Program program, McpTask task) {
        if (program == null) return ProjectToolSupport.error("No program currently loaded");
        try {
            String rangesText = ProjectToolSupport.required(args, "ranges");
            int limit = limit(args.get("max_instructions"));
            List<String> mnemonics = strings(args.get("mnemonics"));
            String operand = args.get("operand_contains") instanceof String s ? s.toLowerCase(Locale.ROOT) : null;
            boolean includeBytes = Boolean.TRUE.equals(args.get("include_bytes"));
            AddressSet set = new AddressSet();
            for (SetRegisterContextTool.AddressRange range : SetRegisterContextTool.parseRanges(program, rangesText))
                set.add(range.start, range.end.subtract(1));
            List<Map<String, Object>> matches = new ArrayList<>();
            int inspected = 0;
            var it = program.getListing().getInstructions(set, true);
            while (it.hasNext() && inspected < limit) {
                if (cancelled(task)) break;
                Instruction ins = it.next(); inspected++;
                String mnemonic = ins.getMnemonicString();
                String text = ins.toString();
                if (!mnemonics.isEmpty() && mnemonics.stream().noneMatch(m -> m.equalsIgnoreCase(mnemonic))) continue;
                if (operand != null && !text.toLowerCase(Locale.ROOT).contains(operand)) continue;
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ins.getAddress().toString()); row.put("mnemonic", mnemonic); row.put("text", text);
                if (includeBytes) row.put("bytes", bytes(program, ins.getAddress(), ins.getLength()));
                matches.add(row);
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ranges", rangesText); result.put("inspected", inspected); result.put("limit", limit);
            result.put("cancelled", cancelled(task)); result.put("truncated", inspected >= limit && it.hasNext()); result.put("matches", matches);
            return ProjectToolSupport.result(result);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
        catch (Exception e) { return ProjectToolSupport.error("Instruction scan failed: " + e.getMessage()); }
    }
    static int limit(Object value) {
        if (value == null) return DEFAULT_LIMIT;
        int result = BatchQuerySupport.integer(Map.of("max_instructions", value), "max_instructions", DEFAULT_LIMIT, MAX_LIMIT);
        if (result < 1 || result > MAX_LIMIT) throw new IllegalArgumentException("max_instructions must be between 1 and " + MAX_LIMIT);
        return result;
    }
    @SuppressWarnings("unchecked") static List<String> strings(Object value) {
        if (value == null) return List.of();
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException("mnemonics must be an array");
        if (list.size() > 256) throw new IllegalArgumentException("At most 256 mnemonics are allowed");
        List<String> result = new ArrayList<>();
        for (Object item : list) if (!(item instanceof String s) || s.isBlank()) throw new IllegalArgumentException("mnemonics entries must be non-empty strings"); else result.add(s.trim());
        return result;
    }
    private static boolean cancelled(McpTask task) { return Thread.currentThread().isInterrupted() || task != null && (task.getStatus() == McpTask.Status.CANCELLED || task.getStatus() == McpTask.Status.CANCEL_REQUESTED); }
    private static String bytes(Program p, Address a, int length) throws Exception {
        byte[] b = new byte[length]; p.getMemory().getBytes(a, b); StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString();
    }
}
