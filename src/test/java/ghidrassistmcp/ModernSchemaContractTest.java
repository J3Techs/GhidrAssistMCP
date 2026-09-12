package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

class ModernSchemaContractTest {
    @Test void fullCatalogBuildsWithSdkSchemaValidationEnabled() {
        var backend = new GhidrAssistMCPBackend();
        var transport = HttpServletStreamableServerTransportProvider.builder()
            .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper())).mcpEndpoint("/mcp").build();
        try {
            var builder = McpServer.sync(transport).serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities()).instructions(backend.getInstructions());
            for (var tool : backend.getAllTools()) {
                builder.toolCall(tool, (exchange, request) -> McpSchema.CallToolResult.builder().addTextContent("fixture").build());
            }
            var server = builder.build();
            try { assertEquals(backend.getAllTools().size(), server.listTools().size()); }
            finally { server.close(); }
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void mapSchemaKeywordsAndOutputContractSurviveRegistrationAndAlias() {
        var backend = new GhidrAssistMCPBackend();
        McpTool tool = new McpTool() {
            public String getName() { return "schema_contract_fixture"; }
            public String getDescription() { return "Schema preservation fixture"; }
            public McpSchema.JsonSchema getInputSchema() { return null; }
            public Map<String, Object> getInputSchemaMap() {
                return Map.of("type", "object", "$defs", Map.of("label", Map.of("type", "string", "minLength", 1)),
                    "properties", Map.of("label", Map.of("$ref", "#/$defs/label")),
                    "required", List.of("label"), "additionalProperties", false);
            }
            public Map<String, Object> getOutputSchema() { return Map.of("type", "object", "required", List.of("ok")); }
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) { throw new UnsupportedOperationException(); }
        };
        try {
            backend.registerTool(tool);
            backend.registerTool(new ToolAlias("schema_contract_alias", tool));
            for (var descriptor : backend.getAllTools().stream().filter(t -> t.name().startsWith("schema_contract_")).toList()) {
                assertEquals(tool.getInputSchemaMap().get("$defs"), descriptor.inputSchema().get("$defs"));
                assertEquals(false, descriptor.inputSchema().get("additionalProperties"));
                assertTrue(((Map<?, ?>) descriptor.inputSchema().get("properties")).containsKey("program_id"));
                assertEquals(tool.getOutputSchema(), descriptor.outputSchema());
                assertTrue(descriptor.annotations().readOnlyHint());
            }
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void legacyNestedSchemaAdaptsToPlainJsonObjects() {
        var schema = new McpSchema.JsonSchema("object", Map.of("name", new McpSchema.JsonSchema("string", null, null, null, null, null)),
            List.of("name"), false, null, null);
        Map<String, Object> normalized = McpSchemas.fromLegacy(schema);
        assertEquals(Map.of("type", "string"), ((Map<?, ?>) normalized.get("properties")).get("name"));
        assertEquals(false, normalized.get("additionalProperties"));
    }
}
