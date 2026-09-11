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
    void everyUpstreamEndpointRemainsRegistered() throws Exception {
        var names = backend.getAllTools().stream().map(McpSchema.Tool::name).collect(Collectors.toSet());
        try (var stream = getClass().getResourceAsStream("/upstream-2.11-tool-names.txt")) {
            assertNotNull(stream);
            for (String name : new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).split("\\R")) {
                if (!name.isBlank() && !name.startsWith("#")) assertTrue(names.contains(name), "Missing upstream endpoint: " + name);
            }
        }
        Set<String> additions = Set.of("save_program", "project_repository", "query_address_context_batch",
            "search_symbols_batch", "read_memory_batch", "read_memory_table", "xrefs_batch",
            "function_inventory", "scan_instructions", "scan_function_candidates", "get_register_context");
        assertTrue(names.containsAll(additions));
        var bsimNames = ghidrassistmcp.bsim.BsimTool.tools().stream().map(McpTool::getName).collect(Collectors.toSet());
        assertTrue(names.containsAll(bsimNames));
        assertEquals(94 + bsimNames.size(), names.size());
    }

    @Test
    void legacyMutatorsAreAdvertisedAsMutating() {
        var tools = backend.getAvailableTools().stream().collect(Collectors.toMap(McpSchema.Tool::name, tool -> tool));
        for (String name : Set.of("write_bytes", "clear_code_ranges", "patch_instruction", "set_register_context",
                "save_program", "project_files", "project_repository", "bulk_transfer_labels")) {
            assertEquals(false, tools.get(name).annotations().readOnlyHint(), name);
        }
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

    @Test
    void contextDecorationPreservesStructuredErrors() {
        backend.registerTool(new McpTool() {
            public String getName() { return "structured_error_test"; }
            public String getDescription() { return "test"; }
            public McpSchema.JsonSchema getInputSchema() { return null; }
            public McpSchema.CallToolResult execute(Map<String, Object> args, ghidra.program.model.listing.Program program) {
                return McpSchema.CallToolResult.builder().isError(true).structuredContent(Map.of("reason", "busy"))
                    .addTextContent("Busy").build();
            }
        });
        var result = backend.callTool("structured_error_test", Map.of());
        assertTrue(result.isError());
        assertEquals(Map.of("reason", "busy"), result.structuredContent());
    }
}
