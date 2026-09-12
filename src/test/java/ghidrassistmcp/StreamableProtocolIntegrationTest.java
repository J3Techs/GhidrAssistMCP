package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.Map;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

/** Real local HTTP client/server contract; never opens or changes a user program. */
class StreamableProtocolIntegrationTest {
    @Test void discoversFullCatalogAndCallsCapabilitiesOverCurrentSdkTransport() throws Exception {
        var backend = new GhidrAssistMCPBackend();
        var server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
        try {
            server.start();
            var transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + server.getLocalPort())
                .endpoint("/mcp").connectTimeout(Duration.ofSeconds(5)).build();
            try (var client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(10)).build()) {
                assertEquals("2025-11-25", client.initialize().protocolVersion());
                assertTrue(client.getServerInstructions().contains("wait_task"));
                assertEquals(backend.getAvailableTools().size(), client.listTools().tools().size());
                assertEquals(1, client.listResources().resources().size());
                assertEquals(6, client.listResourceTemplates().resourceTemplates().size());
                assertEquals(7, client.listPrompts().prompts().size());
                var result = client.callTool(new McpSchema.CallToolRequest("runtime_capabilities", Map.of()));
                assertFalse(Boolean.TRUE.equals(result.isError()));
                Map<?, ?> body = (Map<?, ?>) result.structuredContent();
                assertEquals(backend.getAllTools().size(), ((Number) body.get("registered_tools")).intValue());
                assertEquals(false, ((Map<?, ?>) body.get("protocol")).get("tasks_extension"));
                var invalid = client.callTool(new McpSchema.CallToolRequest("wait_task", Map.of("task_id", 12)));
                assertTrue(Boolean.TRUE.equals(invalid.isError()));
            }
        } finally {
            try { server.stop(); } finally { backend.getTaskManager().shutdown(); }
        }
    }
}
