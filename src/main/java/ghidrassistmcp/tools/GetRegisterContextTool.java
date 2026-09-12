package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/** Read register-context values and gaps over bounded requested ranges. */
public class GetRegisterContextTool implements McpTool {
    @Override public boolean isLongRunning() { return true; }
    @Override public String getName() { return "get_register_context"; }
    @Override public String getDescription() {
        return "Read stored register context over bounded half-open [start,end) ranges, returning actual value segments and gaps.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "register", Map.of("type", "string", "description", "Register name"),
            "ranges", Map.of("type", "string", "description", "Comma-separated start-end ranges"),
            "max_segments", Map.of("type", "integer", "default", 10000)
        ), List.of("register", "ranges"), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return executeRead(args, program, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
                                                       GhidrAssistMCPBackend backend, McpTask task) {
        return executeRead(args, program, task);
    }
    private McpSchema.CallToolResult executeRead(Map<String, Object> args, Program program, McpTask task) {
        if (program == null) return ProjectToolSupport.error("No program currently loaded");
        try {
            String name = ProjectToolSupport.required(args, "register");
            String rangesText = ProjectToolSupport.required(args, "ranges");
            int maxSegments = BatchQuerySupport.integer(args, "max_segments", 10000, 100000);
            if (maxSegments < 1 || maxSegments > 100000) return ProjectToolSupport.error("max_segments must be between 1 and 100000");
            ProgramContext context = program.getProgramContext();
            Register register = context.getRegister(name);
            if (register == null) {
                for (Register candidate : context.getRegisters()) {
                    if (candidate.getName().equalsIgnoreCase(name)) { register = candidate; break; }
                }
            }
            if (register == null) return ProjectToolSupport.error("Register not found: " + name);
            List<SetRegisterContextTool.AddressRange> ranges =
                SetRegisterContextTool.parseRanges(program, rangesText);
            if (ranges.isEmpty()) return ProjectToolSupport.error("No valid ranges specified");
            List<Map<String, Object>> values = new ArrayList<>();
            int emitted = 0;
            for (SetRegisterContextTool.AddressRange range : ranges) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("start", range.start.toString()); row.put("end", range.end.toString());
                List<Map<String, Object>> segments = new ArrayList<>();
                for (SetRegisterContextTool.ValueSegment segment : SetRegisterContextTool.valueSegments(context, register, range, maxSegments - emitted)) {
                    if (cancelled(task)) break;
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("start", segment.start.toString()); item.put("end", segment.end.toString());
                    item.put("value", segment.value == null ? null : "0x" + segment.value.toString(16));
                    item.put("defined", segment.value != null); segments.add(item);
                    emitted++;
                }
                row.put("segments", segments);
                row.put("truncated", cancelled(task));
                row.put("cancelled", cancelled(task));
                values.add(row);
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("register", register.getName()); result.put("ranges", values);
            result.put("sampling", "defined_context_segments_and_gaps");
            return ProjectToolSupport.result(result);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
        catch (Exception e) { return ProjectToolSupport.error("Register context read failed: " + e.getMessage()); }
    }
    private static boolean cancelled(McpTask task) {
        return Thread.currentThread().isInterrupted() || task != null && (task.getStatus() == McpTask.Status.CANCELLED || task.getStatus() == McpTask.Status.CANCEL_REQUESTED);
    }
}
