package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.resources.McpResource;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

/** Tests actual HTTP protocol behavior with synthetic programs/tasks only. */
class AppliedProtocolConformanceTest {
    @Test void actualServerAdvertisesOnlyImplementedCapabilitiesAndReturnsStableToolCatalog() throws Exception {
        var backend = new GhidrAssistMCPBackend();
        try (var wire = new Wire(backend, ignored -> {})) {
            var initialized = wire.client.initialize();
            assertEquals("2025-11-25", initialized.protocolVersion());
            assertFalse(initialized.capabilities().tools().listChanged());
            assertFalse(initialized.capabilities().resources().subscribe());
            assertFalse(initialized.capabilities().resources().listChanged());
            assertFalse(initialized.capabilities().prompts().listChanged());
            assertNull(initialized.capabilities().completions());
            assertTrue(initialized.instructions().contains("Application task IDs"));
            var first = wire.client.listTools().tools();
            assertEquals(first, wire.client.listTools().tools());
            assertEquals(first.stream().map(McpSchema.Tool::name).sorted(String.CASE_INSENSITIVE_ORDER).toList(),
                first.stream().map(McpSchema.Tool::name).toList());
            assertTrue(first.stream().allMatch(t -> t.annotations() != null && t.inputSchema() != null));
            assertTrue(first.stream().filter(t -> t.name().equals("cancel_task"))
                .allMatch(t -> !t.annotations().readOnlyHint()));
            assertEquivalentJsonFallback(wire.client.callTool(new McpSchema.CallToolRequest("runtime_capabilities", Map.of())));
            var omitted = wire.client.callTool(new McpSchema.CallToolRequest("runtime_capabilities", null));
            assertFalse(Boolean.TRUE.equals(omitted.isError()));
            assertEquivalentJsonFallback(omitted);
            assertTrue(wire.client.callTool(new McpSchema.CallToolRequest("wait_task", null)).isError());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void resourceSelectionAndResourceErrorsSurviveTheHttpBoundary() throws Exception {
        Program active = program("active"), target = program("target + name");
        var backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return active; }
            @Override public List<Program> getAllOpenPrograms() {
                return List.of(active, target, program("duplicate"), program("duplicate"));
            }
        };
        backend.getResourceRegistry().registerResource(new McpResource() {
            public String getName() { return "wire_resource_fixture"; }
            public String getUriPattern() { return "ghidra://fixture/{name}"; }
            public String getDescription() { return "Synthetic program selector test"; }
            public String getMimeType() { return "text/plain"; }
            public boolean canHandle(String uri) { return uri.startsWith("ghidra://fixture/"); }
            public Map<String, String> extractParams(String uri) { return Map.of("name", uri.substring("ghidra://fixture/".length())); }
            public String readContent(Program program, Map<String, String> params) { return program.getName(); }
        });
        try (var wire = new Wire(backend, ignored -> {})) {
            wire.client.initialize();
            var read = wire.client.readResource(new McpSchema.ReadResourceRequest("ghidra://fixture/target%20+%20name"));
            assertEquals("target + name", ((McpSchema.TextResourceContents) read.contents().getFirst()).text());
            assertResourceError(wire.client, "ghidra://fixture/missing", -32002);
            assertResourceError(wire.client, "ghidra://fixture/duplicate", -32602);
            assertResourceError(wire.client, "ghidra://fixture/%ZZ", -32602);
            assertResourceError(wire.client, "ghidra://unknown/resource", -32002);
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void sdkValidatesInputBeforeDispatchAndValidatesDeclaredSuccessfulOutput() throws Exception {
        AtomicInteger dispatched = new AtomicInteger();
        McpSchema.Tool fixture = McpSchema.Tool.builder().name("contract_fixture")
            .inputSchema(Map.of("type", "object", "properties", Map.of("value", Map.of("type", "integer")),
                "required", List.of("value"), "additionalProperties", false))
            .outputSchema(Map.of("type", "object", "properties", Map.of("value", Map.of("type", "integer")),
                "required", List.of("value"))).build();
        McpBackend backend = (McpBackend) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[] {McpBackend.class}, (p, m, a) -> switch (m.getName()) {
                case "getAvailableTools" -> List.of(fixture);
                case "getServerInfo" -> new McpSchema.Implementation("contract-fixture", "1");
                case "getInstructions" -> "Synthetic contract test";
                case "getCapabilities" -> McpSchema.ServerCapabilities.builder().tools(false).build();
                case "callTool" -> {
                    dispatched.incrementAndGet();
                    int input = ((Number) ((Map<?, ?>) a[1]).get("value")).intValue();
                    if (input == 2) yield McpSchema.CallToolResult.builder().isError(true).addTextContent("Expected fixture error").build();
                    yield McpSchema.CallToolResult.builder().structuredContent(Map.of("value", input == 0 ? "invalid" : input)).build();
                }
                default -> null;
            });
        try (var wire = new Wire(backend, ignored -> {})) {
            wire.client.initialize();
            var invalidInput = wire.client.callTool(new McpSchema.CallToolRequest("contract_fixture", Map.of("value", "wrong")));
            assertTrue(Boolean.TRUE.equals(invalidInput.isError()));
            assertEquals(0, dispatched.get());
            var invalidOutput = wire.client.callTool(new McpSchema.CallToolRequest("contract_fixture", Map.of("value", 0)));
            assertTrue(Boolean.TRUE.equals(invalidOutput.isError()));
            assertNull(invalidOutput.structuredContent());
            var valid = wire.client.callTool(new McpSchema.CallToolRequest("contract_fixture", Map.of("value", 1)));
            assertFalse(Boolean.TRUE.equals(valid.isError()));
            assertEquals(Map.of("value", 1), valid.structuredContent());
            assertTrue(valid.content().getFirst() instanceof McpSchema.TextContent);
            var expectedError = wire.client.callTool(new McpSchema.CallToolRequest("contract_fixture", Map.of("value", 2)));
            assertTrue(Boolean.TRUE.equals(expectedError.isError()));
            assertEquals("Expected fixture error", ((McpSchema.TextContent) expectedError.content().getFirst()).text());
            McpError unknown = assertThrows(McpError.class,
                () -> wire.client.callTool(new McpSchema.CallToolRequest("missing_fixture", Map.of())));
            assertEquals(-32602, unknown.getJsonRpcError().code());
        }
    }

    @Test void waitProgressIsRequestedCorrelatedIncreasingAndDoesNotCancelTheTask() throws Exception {
        var backend = new GhidrAssistMCPBackend();
        CountDownLatch release = new CountDownLatch(1);
        var notifications = new CopyOnWriteArrayList<McpSchema.ProgressNotification>();
        var task = backend.getTaskManager().submitTask("synthetic_blocked_task", Map.of(), () -> {
            try { assertTrue(release.await(10, TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
            return McpSchema.CallToolResult.builder().addTextContent("complete").build();
        });
        try (var wire = new Wire(backend, notifications::add)) {
            wire.client.initialize();
            var result = wire.client.callTool(new McpSchema.CallToolRequest("wait_task",
                Map.of("task_id", task.getTaskId(), "timeout_ms", 400), Map.of("progressToken", 42)));
            assertFalse(Boolean.TRUE.equals(result.isError()));
            assertEquivalentJsonFallback(result);
            assertEquals("timeout", ((Map<?, ?>) result.structuredContent()).get("wait_outcome"));
            assertFalse(((Map<?, ?>) result.structuredContent()).get("terminal").equals(true));
            assertTrue(notifications.size() >= 2, "Progress must flow during the held tools/call response");
            double previous = -1;
            for (var notification : notifications) {
                assertEquals(42, ((Number) notification.progressToken()).intValue());
                assertTrue(notification.progress() > previous);
                previous = notification.progress();
            }
            int priorCount = notifications.size();
            wire.client.callTool(new McpSchema.CallToolRequest("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 30)));
            assertEquals(priorCount, notifications.size(), "No progress without a request progressToken");
            wire.client.callTool(new McpSchema.CallToolRequest("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 10),
                Map.of("progressToken", "wait-again")));
            assertTrue(notifications.size() > priorCount);
            assertTrue(notifications.subList(priorCount, notifications.size()).stream()
                .allMatch(p -> p.progressToken().equals("wait-again")));
        } finally { release.countDown(); backend.getTaskManager().shutdown(); }
    }

    private static void assertResourceError(McpSyncClient client, String uri, int code) {
        McpError error = assertThrows(McpError.class, () -> client.readResource(new McpSchema.ReadResourceRequest(uri)));
        assertEquals(code, error.getJsonRpcError().code());
    }

    private static void assertEquivalentJsonFallback(McpSchema.CallToolResult result) {
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var expected = mapper.valueToTree(result.structuredContent());
        assertTrue(result.content().stream().filter(McpSchema.TextContent.class::isInstance)
            .map(McpSchema.TextContent.class::cast).anyMatch(text -> {
                try { return expected.equals(mapper.readTree(text.text())); }
                catch (Exception e) { return false; }
            }), "Structured result must include a standalone equivalent serialized JSON text block");
    }

    private static Program program(String name) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] {Program.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "addConsumer" -> true;
                case "isUsedBy" -> true;
                case "release" -> null;
                case "getDomainFile" -> null;
                case "isClosed" -> false;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static final class Wire implements AutoCloseable {
        private final GhidrAssistMCPServer server;
        private final McpSyncClient client;
        private Wire(McpBackend backend, Consumer<McpSchema.ProgressNotification> progress) throws Exception {
            server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
            server.start();
            var transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + server.getLocalPort())
                .endpoint("/mcp").connectTimeout(Duration.ofSeconds(5)).build();
            client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(10)).progressConsumer(progress).build();
        }
        @Override public void close() throws Exception { try { client.close(); } finally { server.stop(); } }
    }
}
