package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.resources.RuntimeCapabilitiesResource;
import io.modelcontextprotocol.spec.McpSchema;

/** Tool-accessible runtime orientation for clients that do not browse resources automatically. */
public final class RuntimeCapabilitiesTool implements McpTool {
    @Override public String getName() { return "runtime_capabilities"; }
    @Override public String getDescription() {
        return "Report the installed build, supported MCP revisions, enabled tool counts, open program identities, "
            + "headless/GUI services and task recovery limits. Read-only; does not probe remote backends.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of("include_programs", new McpSchema.JsonSchema("boolean", null, null, null, null, null)), List.of(), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        var text = Map.of("type", "string");
        var bool = Map.of("type", "boolean");
        var strings = Map.of("type", "array", "items", text);
        var nullableText = Map.of("type", List.of("string", "null"));
        Map<String, Object> identity = new java.util.LinkedHashMap<>();
        for (String key : List.of("program_id", "name", "modification_number", "path", "program_url")) identity.put(key, text);
        identity.put("file_id", nullableText);
        identity.put("version", Map.of("type", "integer"));
        for (String key : List.of("dirty", "changeable", "transaction_active", "read_only", "can_save", "busy")) identity.put(key, bool);
        var program = object(identity, List.of("program_id", "name", "modification_number", "dirty", "changeable", "transaction_active"));
        Map<String, Object> properties = new java.util.LinkedHashMap<>();
        properties.put("schema_version", Map.of("type", "integer", "const", 1));
        properties.put("resource", Map.of("type", "string", "const", "ghidra://runtime/capabilities"));
        properties.put("ghidra_version", text);
        for (String key : List.of("gui", "headless", "async_enabled", "headless_session", "program_manager_available")) properties.put(key, bool);
        for (String key : List.of("registered_tools", "enabled_tools")) properties.put(key, Map.of("type", "integer", "minimum", 0));
        for (String key : List.of("disabled_tools", "unavailable_reasons")) properties.put(key, strings);
        properties.put("active_project", nullableText);
        properties.put("open_programs", Map.of("type", "array", "items", program));
        properties.put("active_program", Map.of("anyOf", List.of(program, Map.of("type", "null"))));
        properties.put("include_programs", bool);
        properties.put("program_count", Map.of("type", "integer", "minimum", 0));
        properties.put("active_program_id", nullableText);
        properties.put("program_id_collisions", strings);
        properties.put("build_info", object(Map.of("available", bool, "revision", text, "dirty", text, "built_at", text, "source_sha256", text, "error", text), List.of("available")));
        var protocol = Map.<String, Object>of("sdk_version", text, "latest_supported_revision", text,
            "supported_revisions", strings, "stateless_2026_07_28", bool, "tasks_extension", bool, "application_task_api", strings);
        properties.put("protocol", object(protocol, List.copyOf(protocol.keySet())));
        properties.put("native_version_tracking", object(Map.of("available", bool, "correlators", strings), List.of("available", "correlators")));
        properties.put("bsim", object(Map.of("api_available", bool, "backend_validation", text), List.of("api_available", "backend_validation")));
        properties.put("tasks", object(Map.of(
            "generic", object(Map.of("durable", bool, "restart_recovery", text), List.of("durable", "restart_recovery")),
            "bsim", object(Map.of("durable_journal", bool, "backend_health", text), List.of("durable_journal", "backend_health"))), List.of("generic", "bsim")));
        var required = new java.util.ArrayList<>(properties.keySet());
        required.removeAll(List.of("open_programs", "active_program", "include_programs", "program_count", "active_program_id", "program_id_collisions"));
        return object(properties, required);
    }
    private static Map<String, Object> object(Map<String, ?> properties, List<String> required) {
        return Map.of("type", "object", "properties", properties, "required", required, "additionalProperties", false);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return execute(args, program, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program, GhidrAssistMCPBackend backend) {
        try {
            Object v=args == null ? null : args.get("include_programs");
            if (v != null && !(v instanceof Boolean)) throw new IllegalArgumentException("include_programs must be boolean");
            return ProjectToolSupport.result(new RuntimeCapabilitiesResource(() -> backend).snapshot(v == null || Boolean.TRUE.equals(v)));
        } catch (Exception e) { return ProjectToolSupport.result(Map.of("schema_version",1,"error",String.valueOf(e.getMessage())),true); }
    }
}
