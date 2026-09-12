package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

class McpOutputContractTest {
    private static McpTool fixture(boolean async, boolean valid) {
        return new McpTool() {
            public String getName() { return "output_contract_fixture"; }
            public String getDescription() { return "Output contract fixture"; }
            public McpSchema.JsonSchema getInputSchema() { return new McpSchema.JsonSchema("object", Map.of(), List.of(), false, null, null); }
            public boolean isLongRunning() { return async; }
            public boolean isCacheable() { return true; }
            public Map<String, Object> getOutputSchema() {
                return Map.of("type", "object", "$defs", Map.of("count", Map.of("type", "integer", "minimum", 0)),
                    "properties", Map.of("count", Map.of("$ref", "#/$defs/count")), "required", List.of("count"), "additionalProperties", false);
            }
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                return McpSchema.CallToolResult.builder().structuredContent(Map.of("count", valid ? 1 : "invalid"))
                    .addTextContent("Fixture result").build();
            }
        };
    }

    @Test void asyncUnionPreservesRootReferencesAndRejectsUnrelatedObjects() {
        var tool = fixture(true, true);
        var schema = McpOutputSchemas.advertised(tool);
        var validator = McpJsonDefaults.getSchemaValidator();
        assertTrue(validator.validate(schema, Map.of("count", 3)).valid());
        assertFalse(validator.validate(schema, Map.of("count", "invalid")).valid());
        assertFalse(validator.validate(schema, Map.of("unrelated", true)).valid());
        var backend = new GhidrAssistMCPBackend();
        try {
            var task = new McpTask(tool.getName(), Map.of());
            assertTrue(validator.validate(schema, backend.getTaskManager().waitForTaskSnapshot(task)).valid());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void backendRejectsMalformedCompletionsBeforeTaskSuccess() throws Exception {
        for (boolean async : List.of(false, true)) {
            Program target = CacheExecutionTest.program("schema-cache-fixture", new java.util.concurrent.atomic.AtomicLong());
            var backend = new GhidrAssistMCPBackend() {
                @Override public Program getCurrentProgram() { return target; }
                @Override public List<Program> getAllOpenPrograms() { return List.of(target); }
            };
            try {
                backend.setAsyncExecutionEnabled(async);
                backend.registerTool(fixture(async, false));
                var response = backend.callTool("output_contract_fixture", Map.of());
                if (!async) assertTrue(response.isError());
                else {
                    var task = backend.getTaskManager().listTasks(null).stream()
                        .filter(t -> t.getToolName().equals("output_contract_fixture")).findFirst().orElseThrow();
                    task.awaitSnapshot(TimeUnit.SECONDS.toMillis(5), null);
                    assertEquals(McpTask.Status.FAILED, task.getStatus());
                    assertTrue(task.getResult().isError());
                }
                assertEquals(0, backend.getCache().size(), "Invalid completion must not warm the cache");
                backend.setAsyncExecutionEnabled(false);
                backend.registerTool(fixture(false, true));
                assertFalse(Boolean.TRUE.equals(backend.callTool("output_contract_fixture", Map.of()).isError()));
                assertEquals(1, backend.getCache().size(), "A valid completion does warm the same cache");
            } finally { backend.getTaskManager().shutdown(); }
        }
    }

    @Test void jsonFallbackSurvivesContextAndPreservesOtherContentAndMetadata() throws Exception {
        var mapper = new ObjectMapper();
        var data = Map.<String, Object>of("count", 2L);
        for (String text : List.of("Two matches", "{\"count\":2}", "[Context] Operating on: fixture\n\n{\"count\":2}")) {
            var input = McpSchema.CallToolResult.builder().addTextContent(text).structuredContent(data)
                .meta(Map.of("example", "metadata")).build();
            var result = McpResultContent.withJsonFallback(input);
            assertEquals(input.structuredContent(), result.structuredContent());
            assertEquals(input.meta(), result.meta());
            long jsonBlocks = result.content().stream().filter(c -> {
                if (!(c instanceof McpSchema.TextContent t)) return false;
                try { return mapper.readTree(mapper.writeValueAsString(data)).equals(mapper.readTree(t.text())); }
                catch (Exception ignored) { return false; }
            }).count();
            assertEquals(1, jsonBlocks);
            assertEquals(result, McpResultContent.withJsonFallback(result));
        }
    }

    @Test void declaredContractDoesNotOverwriteExistingToolErrors() {
        var error = McpSchema.CallToolResult.builder().isError(true).addTextContent("Original failure").build();
        assertSame(error, McpOutputSchemas.validateCompletion(fixture(true, true), error));
    }
}
