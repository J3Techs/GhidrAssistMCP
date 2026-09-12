package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

class BackendRequestMetricsTest {
    private static final class Tool implements McpTool {
        final AtomicInteger calls = new AtomicInteger();
        public String getName() { return "metrics_fixture"; }
        public boolean isLongRunning() { return true; }
        public String getDescription() { return "metrics fixture"; }
        public McpSchema.JsonSchema getInputSchema() { return new McpSchema.JsonSchema("object", Map.of(), java.util.List.of(), null, null, null); }
        public McpSchema.CallToolResult execute(Map<String,Object> args, Program program) {
            calls.incrementAndGet();
            return McpSchema.CallToolResult.builder().structuredContent(Map.of("text", "héllo 世界")).addTextContent("done").build();
        }
    }

    @Test void synchronousDispatchRecordsSelectionExecutionSerializationAndPrivacy() {
        var backend = new GhidrAssistMCPBackend();
        try {
            backend.setAsyncExecutionEnabled(false); backend.registerTool(new Tool());
            var response = backend.callTool("metrics_fixture", Map.of("secret", "do not retain"));
            assertFalse(Boolean.TRUE.equals(response.isError()));
            var records = backend.getRequestMetrics();
            assertEquals(1, records.size());
            var record = records.getFirst();
            assertEquals("submission", record.kind());
            assertTrue(record.durationsMillis().containsKey("selection"));
            assertTrue(record.durationsMillis().containsKey("execution"));
            assertTrue(record.durationsMillis().containsKey("serialization"));
            assertTrue(record.encodedResultBytes() > 0);
            assertEquals("metrics_fixture", record.toolName());
        } finally { backend.shutdownWorkers(); }
    }

    @Test void asyncDispatchUsesSharedCorrelationForSubmissionAndWorker() throws Exception {
        var backend = new GhidrAssistMCPBackend();
        try {
            backend.setAsyncReadGraceMillis(0); var tool = new Tool(); backend.registerTool(tool);
            var response = backend.callTool("metrics_fixture", Map.of());
            assertNotNull(response.structuredContent());
            for (int i = 0; i < 100 && backend.getRequestMetrics().size() < 2; i++) Thread.sleep(5);
            var records = backend.getRequestMetrics();
            assertEquals(2, records.size());
            assertEquals(records.get(0).correlationId(), records.get(1).correlationId());
            var worker = records.stream().filter(r -> r.kind().equals("worker_completion")).findFirst().orElseThrow();
            var submission = records.stream().filter(r -> r.kind().equals("submission")).findFirst().orElseThrow();
            assertEquals(worker.correlationId(), submission.correlationId());
            assertTrue(worker.durationsMillis().containsKey("queue"));
            assertTrue(worker.durationsMillis().containsKey("writer_guard"));
            assertTrue(worker.durationsMillis().containsKey("execution"));
        } finally { backend.shutdownWorkers(); }
    }

    @Test void unknownToolUsesPrivacySafeCanonicalName() {
        var backend = new GhidrAssistMCPBackend();
        try { backend.callTool(null, Map.of("secret", "value")); assertEquals("unknown", backend.getRequestMetrics().getFirst().toolName()); }
        finally { backend.shutdownWorkers(); }
    }
}
