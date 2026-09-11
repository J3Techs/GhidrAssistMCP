package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import io.modelcontextprotocol.spec.McpSchema;

class CustomCompatibilityTest {
    private final GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();

    @AfterEach
    void shutDown() { backend.getTaskManager().shutdown(); }

    @Test
    void discoversAllCustomToolsAndLegacySchemasAlongsideUpstream() {
        Map<String, McpSchema.Tool> tools = backend.getAvailableTools().stream()
            .collect(Collectors.toMap(McpSchema.Tool::name, tool -> tool));
        Set<String> custom = Set.of("write_bytes", "clear_code_ranges", "set_register_context",
            "run_script", "patch_instruction", "create_memory_block", "export_function_signatures",
            "function_byte_matcher", "string_anchor_matcher", "bulk_transfer_labels",
            "create_functions_at_addresses", "bulk_region_transfer");
        assertTrue(tools.keySet().containsAll(custom), () -> "Missing custom tools: " +
            custom.stream().filter(name -> !tools.containsKey(name)).toList());
        for (String name : Set.of("get_data_type", "delete_data_type", "list_data_types",
                "set_function_prototype", "set_local_variable_type", "set_data_type",
                "set_comment", "get_call_graph", "get_functions", "analyze_program")) {
            assertTrue(tools.containsKey(name), name);
        }
        assertEquals(tools.get("get_functions").inputSchema(), tools.get("list_functions").inputSchema());
        assertTrue(tools.get("list_functions").inputSchema().properties().containsKey("match_mode"));
        assertTrue(tools.get("set_local_variable_type").inputSchema().required().contains("variable_name"));
        assertTrue(tools.get("run_script").inputSchema().properties().containsKey("max_output_chars"));
        assertFalse(tools.containsKey("scripts"));
        assertFalse(tools.containsKey("import_file"));
        assertFalse(tools.containsKey("export_program"));
    }

    @Test
    void disablingEitherNameDisablesBothDiscoveryAndExecution() {
        backend.setToolEnabled("get_functions", false);
        assertFalse(backend.isToolEnabled("list_functions"));
        assertFalse(backend.getAvailableTools().stream().anyMatch(t ->
            Set.of("list_functions", "get_functions").contains(t.name())));
        assertTrue(backend.callTool("list_functions", Map.of()).isError());
        backend.setToolEnabled("list_functions", true);
        assertTrue(backend.isToolEnabled("get_functions"));
    }

    @Test
    void oldPreferencesAndSingleCheckboxChangesUpdateSharedAliasState() {
        backend.updateToolEnabledStates(Map.of("list_functions", false, "get_functions", true));
        assertFalse(backend.isToolEnabled("get_functions"));
        Map<String, Boolean> states = new HashMap<>(backend.getToolEnabledStates());
        states.put("get_functions", true);
        backend.updateToolEnabledStates(states);
        assertTrue(backend.isToolEnabled("list_functions"));
        assertTrue(backend.isToolEnabled("get_functions"));
    }

    @Test
    void legacyReadAliasUsesTheSameExecutionPath() {
        assertEquals(backend.callTool("get_binary_info", Map.of()).content(),
                     backend.callTool("get_program_info", Map.of()).content());
    }

    @Test
    void unregisteringCanonicalToolRemovesItsLegacyEndpoint() {
        backend.unregisterTool("get_functions");
        assertFalse(backend.getAllTools().stream().anyMatch(t ->
            Set.of("get_functions", "list_functions").contains(t.name())));
    }
}
