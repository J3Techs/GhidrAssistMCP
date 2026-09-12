package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;
import io.modelcontextprotocol.spec.McpSchema;

class TaskResultWaitTest {
    @Test void waitIncludesCompleteErrorPayloadWithoutChangingOperationStatus() {
        var backend = new GhidrAssistMCPBackend();
        try {
            var task = backend.getTaskManager().submitTask("error", Map.of(), () ->
                McpSchema.CallToolResult.builder().isError(true).structuredContent(Map.of("why", "fixture"))
                    .addTextContent("fixture").build());
            var r = backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 2000, "include_result", true));
            var data = (Map<?,?>) r.structuredContent();
            assertFalse(Boolean.TRUE.equals(r.isError()));
            assertEquals("FAILED", data.get("status"));
            assertEquals("included", data.get("result_status"));
            assertEquals(true, ((Map<?,?>)data.get("operation_result")).get("isError"));
        } finally { backend.shutdownWorkers(); }
    }

    @Test void oversizedPayloadRemainsRetrievableAndDefaultWaitOmitsIt() {
        var backend = new GhidrAssistMCPBackend();
        try {
            var payload = McpSchema.CallToolResult.builder().addTextContent("界".repeat(4000)).build();
            var task = backend.getTaskManager().submitTask("large", Map.of(), () -> payload);
            var r = backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 2000,
                "include_result", true, "max_result_bytes", 1024));
            var data = (Map<?,?>)r.structuredContent();
            assertEquals("too_large", data.get("result_status"));
            assertFalse(data.containsKey("operation_result"));
            assertSame(payload, task.getResult());
            var old = (Map<?,?>)backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 0)).structuredContent();
            assertFalse(old.containsKey("result_status"));
        } finally { backend.shutdownWorkers(); }
    }

    @Test void timeoutDoesNotCancelAndMalformedOptionsFail() {
        var backend = new GhidrAssistMCPBackend();
        var release = new CountDownLatch(1);
        try {
            var task = backend.getTaskManager().submitTask("pending", Map.of(), () -> {
                try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                return McpSchema.CallToolResult.builder().addTextContent("done").build();
            });
            var r = backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 0, "include_result", true));
            assertEquals("not_ready", ((Map<?,?>)r.structuredContent()).get("result_status"));
            assertFalse(task.isTerminal());
            assertTrue(backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "include_result", "true")).isError());
            assertTrue(backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "max_result_bytes", 1.5)).isError());
        } finally { release.countDown(); backend.shutdownWorkers(); }
    }
}
