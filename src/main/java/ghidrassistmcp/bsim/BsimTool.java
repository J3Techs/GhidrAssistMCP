package ghidrassistmcp.bsim;

import java.util.*;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.*;
import io.modelcontextprotocol.spec.McpSchema;

/** MCP schema and result adapter for native BSim operations. */
public final class BsimTool implements McpTool {
    private final BsimOperation operation;
    private final String control;
    private BsimTool(BsimOperation operation, String control) { this.operation = operation; this.control = control; }
    public static List<McpTool> tools() {
        List<McpTool> tools = new ArrayList<>();
        for (var operation : BsimRuntime.operations()) tools.add(new BsimTool(operation, null));
        for (String name : List.of("list_jobs", "get_job", "get_results", "resume_job", "cancel_job", "purge_job")) tools.add(new BsimTool(null, name));
        return List.copyOf(tools);
    }
    @Override public String getName() { return "bsim_" + (operation == null ? control : operation.name()); }
    @Override public String getDescription() {
        if (operation == null) return "BSim durable job control: " + control + ". Results are paged; restart never automatically resumes work. Purge removes the job journal and results, retaining exported corpus artifacts.";
        return operation.description() + (operation.longRunning() ? " Returns a durable job ID immediately; use bsim_get_job and bsim_get_results to inspect completion." : "");
    }
    @Override public boolean isReadOnly() { return operation != null ? operation.readOnly() && !operation.longRunning() : Set.of("list_jobs", "get_job", "get_results").contains(control); }
    @Override public boolean isDestructive() { return operation != null ? operation.destructive() : "purge_job".equals(control); }
    @Override public boolean isOpenWorld() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        List<String> required;
        if (operation != null) {
            properties.put("database", BsimSupport.stringProperty("Saved BSim connection profile ID"));
            properties.put("database_url", BsimSupport.stringProperty("Explicit native BSim URL, without a password"));
            properties.put("profile_id", BsimSupport.stringProperty("Saved BSim connection profile ID"));
            properties.put("project_url", BsimSupport.stringProperty("Local/shared Ghidra project URL"));
            properties.put("project_folder", BsimSupport.stringProperty("Ghidra project folder to process"));
            properties.put("programs", Map.of("type", "array", "items", Map.of("type", "string")));
            properties.put("addresses", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Optional exact hexadecimal function entry points"));
            properties.put("recursive", Map.of("type", "boolean", "default", true));
            properties.put("result_limit", Map.of("type", "integer", "minimum", 1, "maximum", 1000, "default", 100));
            properties.putAll(operation.properties()); required = operation.required();
        } else {
            properties.put("job_id", BsimSupport.stringProperty("Persistent BSim job UUID"));
            properties.put("field", BsimSupport.stringProperty("Optional result array field"));
            properties.put("offset", Map.of("type", "integer", "minimum", 0));
            properties.put("limit", Map.of("type", "integer", "minimum", 1, "maximum", 1000, "default", 100));
            properties.put("confirm", Map.of("type", "boolean"));
            required = control.equals("list_jobs") ? List.of() : List.of("job_id");
        }
        return new McpSchema.JsonSchema("object", properties, required, false, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) { return execute(args, program, null); }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program, GhidrAssistMCPBackend backend) {
        try {
            return BsimSupport.result(operation == null ? BsimRuntime.instance().control(control, args, backend)
                : BsimRuntime.instance().execute(operation, args, program, backend));
        } catch (Exception e) {
            if (e instanceof java.util.concurrent.ExecutionException && e.getCause() instanceof Exception cause) e = cause;
            return BsimSupport.error(e);
        }
    }
}
