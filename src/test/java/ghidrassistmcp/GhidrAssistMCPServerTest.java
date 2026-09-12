package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.resources.McpResource;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

class GhidrAssistMCPServerTest {
    @Test void expectedResourceSelectionFailuresHaveProtocolErrorCodes() {
        var resource = new Resource("program_info", "ghidra://program/{name}/info");
        String uri = "ghidra://program/missing/info";
        var missing = assertThrows(io.modelcontextprotocol.spec.McpError.class,
            () -> GhidrAssistMCPServer.readResourceResult(resource, uri, ignored -> { throw new ProgramIdentity.NotOpenException("missing"); }));
        assertEquals(io.modelcontextprotocol.spec.McpError.RESOURCE_NOT_FOUND.apply(uri).getJsonRpcError().code(), missing.getJsonRpcError().code());
        var invalid = assertThrows(io.modelcontextprotocol.spec.McpError.class,
            () -> GhidrAssistMCPServer.readResourceResult(resource, uri, ignored -> { throw new IllegalArgumentException("Ambiguous selector"); }));
        assertEquals(McpSchema.ErrorCodes.INVALID_PARAMS, invalid.getJsonRpcError().code());
    }
    @Test void resourceDiscoverySeparatesTemplatesFromConcreteUris() {
        var provider = HttpServletStreamableServerTransportProvider.builder()
            .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper())).mcpEndpoint("/mcp").build();
        var builder = McpServer.sync(provider).serverInfo("resource-test", "1")
            .capabilities(McpSchema.ServerCapabilities.builder().resources(false, false).build());
        GhidrAssistMCPServer.registerResourceSpecifications(builder,
            List.of(new Resource("program_info", "ghidra://program/{name}/info"),
                new Resource("runtime", "ghidra://runtime/capabilities")), uri -> "{}");
        var server = builder.build();
        try {
            assertEquals(List.of("ghidra://runtime/capabilities"),
                server.listResources().stream().map(McpSchema.Resource::uri).toList());
            assertEquals(List.of("ghidra://program/{name}/info"),
                server.listResourceTemplates().stream().map(McpSchema.ResourceTemplate::uriTemplate).toList());
        } finally { server.close(); }
    }

    @Test void serverCanRestartAndRejectsDuplicateStart() throws Exception {
        var server = new GhidrAssistMCPServer("127.0.0.1", 0, emptyBackend());
        try {
            server.start();
            assertTrue(server.isRunning());
            assertThrows(IllegalStateException.class, server::start);
            server.stop();
            assertFalse(server.isRunning());
            server.stop();
            server.start();
            assertTrue(server.isRunning());
        } finally { server.stop(); }
    }

    @Test void failedListenerStartCanBeRetriedAfterPortIsReleased() throws Exception {
        GhidrAssistMCPServer server;
        try (var occupied = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            server = new GhidrAssistMCPServer("127.0.0.1", occupied.getLocalPort(), emptyBackend());
            assertThrows(Exception.class, server::start);
            assertFalse(server.isRunning());
            assertEquals("null", server.getState());
        }
        try {
            server.start();
            assertTrue(server.isRunning());
        } finally { server.stop(); }
    }

    private McpBackend emptyBackend() {
        return (McpBackend) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[] {McpBackend.class}, (p, m, a) -> switch (m.getName()) {
                case "getAvailableTools" -> List.of();
                case "getServerInfo" -> new McpSchema.Implementation("lifecycle-test", "1");
                case "getCapabilities" -> McpSchema.ServerCapabilities.builder().build();
                case "getInstructions" -> "Local lifecycle test";
                default -> null;
            });
    }

    private record Resource(String getName, String getUriPattern) implements McpResource {
        public String getDescription() { return "Test resource"; }
        public String getMimeType() { return "application/json"; }
        public String readContent(Program program, Map<String, String> params) { return "{}"; }
        public boolean canHandle(String uri) { return true; }
        public Map<String, String> extractParams(String uri) { return Map.of(); }
    }
}
