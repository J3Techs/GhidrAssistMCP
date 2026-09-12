package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskManager;
import io.modelcontextprotocol.spec.McpSchema;

class McpTaskManagerWorkflowTest {
    @Test
    void nonCooperativeCancellationSettlesAndRetainsResult() throws Exception {
        McpTaskManager manager = new McpTaskManager(1);
        try {
            CountDownLatch started = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            McpTask task = manager.submitTask("slow", Map.of(), ignored -> {
                started.countDown();
                while (release.getCount() != 0) {
                    try { release.await(10, TimeUnit.MILLISECONDS); } catch (InterruptedException ignoredInterrupt) { /* deliberately noncooperative */ }
                }
                return McpSchema.CallToolResult.builder().structuredContent(Map.of("partial", true)).addTextContent("finished").build();
            });
            assertTrue(started.await(1, TimeUnit.SECONDS));
            assertTrue(manager.cancelTask(task.getTaskId()));
            assertEquals(McpTask.Status.CANCEL_REQUESTED, task.getStatus());
            assertFalse(task.isTerminal());
            release.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (!task.isTerminal() && System.nanoTime() < deadline) Thread.yield();
            assertEquals(McpTask.Status.COMPLETED, task.getStatus());
            assertEquals(Map.of("partial", true), task.getResult().structuredContent());
        } finally { manager.shutdown(); }
    }

    @Test
    void queuedCancellationSettlesImmediately() throws Exception {
        McpTaskManager manager = new McpTaskManager(1);
        try {
            CountDownLatch release = new CountDownLatch(1);
            manager.submitTask("blocking", Map.of(), ignored -> { try { release.await(); } catch (InterruptedException ignoredInterrupt) { } return McpSchema.CallToolResult.builder().addTextContent("ok").build(); });
            McpTask queued = manager.submitTask("queued", Map.of(), ignored -> McpSchema.CallToolResult.builder().addTextContent("unexpected").build());
            assertTrue(manager.cancelTask(queued.getTaskId()));
            assertEquals(McpTask.Status.CANCELLED, queued.getStatus());
            release.countDown();
        } finally { manager.shutdown(); }
    }

    @Test
    void errorResultIsRetainedAsFailedOutcome() throws Exception {
        McpTaskManager manager = new McpTaskManager(1);
        try {
            McpTask task = manager.submitTask("error", Map.of(), ignored -> McpSchema.CallToolResult.builder()
                .isError(true).structuredContent(Map.of("reason", "busy")).addTextContent("busy").build());
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (!task.isTerminal() && System.nanoTime() < deadline) Thread.yield();
            assertEquals(McpTask.Status.FAILED, task.getStatus());
            assertEquals(Map.of("reason", "busy"), task.getResult().structuredContent());
        } finally { manager.shutdown(); }
    }
}
