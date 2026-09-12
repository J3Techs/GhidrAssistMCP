package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Discover missing function definitions from existing instructions and call/jump targets. */
public class ScanFunctionCandidatesTool implements McpTool {
    private static final int DEFAULT_LIMIT = 1000, MAX_LIMIT = 100000;
    @Override public String getName() { return "scan_function_candidates"; }
    @Override public String getDescription() {
        return "Find bounded executable instruction or call/jump targets without functions; preview by default. Apply is atomic: any failure or cancellation rolls back the entire call.";
    }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean isIdempotent() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "ranges", Map.of("type", "string", "description", "Comma-separated half-open [start,end) ranges"),
            "mode", Map.of("type", "string", "enum", List.of("preview", "apply"), "default", "preview"),
            "candidate_kind", Map.of("type", "string", "enum", List.of("call_targets", "undefined_starts", "both"), "default", "both"),
            "max_candidates", Map.of("type", "integer", "default", DEFAULT_LIMIT)
        ), List.of("ranges"), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) { return run(args, program, null); }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
                                                       GhidrAssistMCPBackend backend, McpTask task) { return run(args, program, task); }
    private McpSchema.CallToolResult run(Map<String, Object> args, Program program, McpTask task) {
        if (program == null) return ProjectToolSupport.error("No program currently loaded");
        try {
            String rangesText = ProjectToolSupport.required(args, "ranges");
            int limit = ScanInstructionsTool.limit(args.get("max_candidates"));
            String mode = args.get("mode") instanceof String s ? s : "preview";
            String kind = args.get("candidate_kind") instanceof String s ? s : "both";
            if (!mode.equals("preview") && !mode.equals("apply")) throw new IllegalArgumentException("mode must be preview or apply");
            if (!List.of("call_targets", "undefined_starts", "both").contains(kind)) throw new IllegalArgumentException("invalid candidate_kind");
            AddressSet set = new AddressSet();
            for (SetRegisterContextTool.AddressRange r : SetRegisterContextTool.parseRanges(program, rangesText)) set.add(r.start, r.end.subtract(1));
            Map<String, Map<String, Object>> candidates = new LinkedHashMap<>();
            var it = program.getListing().getInstructions(set, true); int inspected = 0;
            while (it.hasNext() && inspected < limit * 4) {
                if (cancelled(task)) break;
                Instruction ins = it.next(); inspected++;
                if (kind.equals("undefined_starts") || kind.equals("both")) {
                    if (program.getFunctionManager().getFunctionContaining(ins.getAddress()) == null && isStart(program, ins))
                        add(candidates, ins.getAddress(), "undefined_instruction");
                }
                if (kind.equals("call_targets") || kind.equals("both")) {
                    for (Reference ref : ins.getReferencesFrom()) {
                        if ((ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) && set.contains(ref.getToAddress())
                                && program.getFunctionManager().getFunctionAt(ref.getToAddress()) == null
                                && program.getFunctionManager().getFunctionContaining(ref.getToAddress()) == null)
                            if (candidates.size() < limit)
                                add(candidates, ref.getToAddress(), ref.getReferenceType().isCall() ? "call_target" : "jump_target");
                    }
                }
                if (candidates.size() >= limit) break;
            }
            List<Map<String, Object>> rows = new ArrayList<>(candidates.values()); rows.sort(Comparator.comparing(x -> (String)x.get("address")));
            int created = 0, skipped = 0, failed = 0, rolledBack = 0;
            ghidra.util.task.TaskMonitor monitor = task != null
                ? new McpTaskMonitor(task, 0, 100, "Function candidates") : new ConsoleTaskMonitor();
            int tx = -1;
            if (mode.equals("apply")) {
                if (program.getCurrentTransactionInfo() != null) return ProjectToolSupport.error("Program has an active transaction");
                tx = program.startTransaction("Scan Function Candidates");
            }
            try {
                for (Map<String, Object> row : rows) {
                    if (cancelled(task)) break;
                    try {
                    Address address = program.getAddressFactory().getAddress((String) row.get("address"));
                    var block = program.getMemory().getBlock(address);
                    if (block == null || !block.isExecute()) { row.put("status", "rejected_non_executable"); failed++; continue; }
                    if (program.getFunctionManager().getFunctionAt(address) != null ||
                        program.getFunctionManager().getFunctionContaining(address) != null) {
                        row.put("status", "skipped_existing_or_containing"); skipped++; continue;
                    }
                    if (mode.equals("preview")) { row.put("status", "would_create"); continue; }
                    boolean dis = new DisassembleCommand(address, set, true).applyTo(program, monitor);
                    boolean ok = new CreateFunctionCmd(address).applyTo(program, monitor);
                    if (ok) { row.put("status", "created"); created++; } else { row.put("status", "failed"); row.put("disassembled", dis); failed++; }
                    } catch (Exception e) {
                        row.put("status", "failed"); row.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()); failed++;
                    }
                }
                if (tx >= 0) {
                    if (cancelled(task) || failed > 0) {
                        program.endTransaction(tx, false);
                        rolledBack = created;
                        created = 0;
                        for (Map<String, Object> row : rows) {
                            if ("created".equals(row.get("status"))) row.put("status", cancelled(task) ? "rolled_back_cancelled" : "rolled_back_failure");
                            if (Boolean.TRUE.equals(row.get("disassembled"))) row.put("disassembly_rolled_back", true);
                        }
                    } else {
                        program.endTransaction(tx, true);
                    }
                    tx = -1;
                }
            } catch (Exception e) { if (tx >= 0) program.endTransaction(tx, false); throw e; }
            Map<String, Object> result = new LinkedHashMap<>(); result.put("mode", mode); result.put("ranges", rangesText);
            result.put("inspected_instructions", inspected); result.put("candidates", rows); result.put("created", created);
            result.put("rolled_back", rolledBack);
            result.put("committed", mode.equals("apply") && !cancelled(task) && failed == 0);
            result.put("skipped", skipped); result.put("failed", failed); result.put("cancelled", cancelled(task));
            result.put("truncated", candidates.size() >= limit || inspected >= limit * 4);
            return ProjectToolSupport.result(result, mode.equals("apply") && (failed > 0 || cancelled(task)));
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
        catch (Exception e) { return ProjectToolSupport.error("Candidate scan failed: " + e.getMessage()); }
    }
    private static boolean isStart(Program p, Instruction ins) {
        Address address = ins.getAddress();
        if (address.equals(address.getAddressSpace().getMinAddress())) return true;
        Instruction previous = p.getListing().getInstructionContaining(address.subtract(1));
        return previous == null;
    }
    private static void add(Map<String, Map<String, Object>> map, Address address, String reason) {
        map.computeIfAbsent(address.toString(), k -> { Map<String, Object> r = new LinkedHashMap<>(); r.put("address", k); r.put("reasons", new ArrayList<String>()); return r; });
        @SuppressWarnings("unchecked") List<String> reasons = (List<String>) map.get(address.toString()).get("reasons"); if (!reasons.contains(reason)) reasons.add(reason);
    }
    private static boolean cancelled(McpTask task) { return Thread.currentThread().isInterrupted() || task != null && (task.getStatus() == McpTask.Status.CANCELLED || task.getStatus() == McpTask.Status.CANCEL_REQUESTED); }
}
