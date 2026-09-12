package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTaskManager;
import io.modelcontextprotocol.spec.McpSchema;

class TaskAdmissionRetentionTest {
    @Test
    void finiteAdmissionRejectsAndRunsCleanupExactlyOnce() throws Exception {
        var manager = new McpTaskManager(1, 1);
        var gate = new CountDownLatch(1); var cleaned = new AtomicInteger();
        try {
            manager.submitTask("hold", Map.of(), () -> { await(gate); return ok("hold"); });
            manager.submitTask("queued", Map.of(), () -> ok("queued"));
            assertThrows(RejectedExecutionException.class,
                () -> manager.submitTask("rejected", Map.of(), McpProgramContext.empty(), task -> ok("rejected"), cleaned::incrementAndGet));
            assertEquals(1, cleaned.get());
            gate.countDown();
        } finally { gate.countDown(); manager.shutdown(); }
    }

    @Test
    void cancellingQueuedTaskFreesQueueSlot() throws Exception {
        var manager = new McpTaskManager(1, 1); var gate = new CountDownLatch(1);
        try {
            manager.submitTask("hold", Map.of(), () -> { await(gate); return ok("hold"); });
            McpTask queued = manager.submitTask("queued", Map.of(), () -> ok("queued"));
            assertTrue(manager.cancelTask(queued.getTaskId()));
            McpTask replacement = manager.submitTask("replacement", Map.of(), () -> ok("replacement"));
            gate.countDown();
            awaitTerminal(replacement);
            assertEquals(McpTask.Status.COMPLETED, replacement.getStatus());
        } finally { gate.countDown(); manager.shutdown(); }
    }

    @Test
    void tinyPayloadLimitsPreserveTerminalOutcomeAndRetentionCode() throws Exception {
        var manager = new McpTaskManager(1, 2, 1024, 512, 8, 60_000);
        try {
            McpTask tooLarge = manager.submitTask("large", Map.of(), () ->
                McpSchema.CallToolResult.builder().structuredContent(Map.of("payload", "x".repeat(1000))).addTextContent("large").build());
            awaitTerminal(tooLarge);
            assertEquals(McpTask.Status.COMPLETED, tooLarge.getStatus());
            assertEquals("RESULT_TOO_LARGE", tooLarge.getResultRetentionCode());
            assertNull(tooLarge.getResult());
            var retrieval = manager.getTaskResult(tooLarge.getTaskId());
            assertTrue(retrieval.isError());
            assertEquals("RESULT_TOO_LARGE", ((Map<?, ?>)retrieval.structuredContent()).get("code"));
            assertEquals("COMPLETED", ((Map<?, ?>)retrieval.structuredContent()).get("operation_status"));

            McpTask failed = manager.submitTask("failed", Map.of(), () ->
                McpSchema.CallToolResult.builder().isError(true).addTextContent("expected failure").build());
            awaitTerminal(failed);
            assertEquals(McpTask.Status.FAILED, failed.getStatus());
            assertNotNull(failed.getResult());
            assertNull(failed.getResultRetentionCode());
        } finally { manager.shutdown(); }
    }

    @Test
    void aggregateBudgetEvictsOldPayloadWithoutChangingStatus() throws Exception {
        long onePayload = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(ok("one")).length; var manager = new McpTaskManager(1, 2, onePayload, 512, 8, 60_000);
        try {
            McpTask first = manager.submitTask("first", Map.of(), () -> ok("one")); awaitTerminal(first);
            McpTask second = manager.submitTask("second", Map.of(), () -> ok("two")); awaitTerminal(second);
            assertEquals(McpTask.Status.COMPLETED, first.getStatus());
            assertEquals(McpTask.Status.COMPLETED, second.getStatus());
            assertEquals("RESULT_EXPIRED", first.getResultRetentionCode());
            assertNotNull(second.getResult());
        } finally { manager.shutdown(); }
    }

    @Test
    void concurrentCompletionsNeverExceedSharedPayloadBudget() throws Exception {
        var manager = new McpTaskManager(4, 4, 240, 1000, 16, 60_000);
        var start = new CountDownLatch(1);
        try {
            var tasks = new java.util.ArrayList<McpTask>();
            for (int i = 0; i < 4; i++) {
                tasks.add(manager.submitTask("concurrent-" + i, Map.of(), () -> {
                    await(start); return ok("payload-" + "x".repeat(20));
                }));
            }
            start.countDown();
            for (McpTask task : tasks) awaitTerminal(task);
            long retained = tasks.stream().mapToLong(McpTask::getRetainedResultBytes).sum();
            assertTrue(retained <= 240, "retained bytes=" + retained);
            assertTrue(tasks.stream().allMatch(McpTask::isTerminal));
            assertTrue(tasks.stream().anyMatch(t -> "RESULT_EXPIRED".equals(t.getResultRetentionCode())));
        } finally { start.countDown(); manager.shutdown(); }
    }

    private static McpSchema.CallToolResult ok(String value) {
        return McpSchema.CallToolResult.builder().addTextContent(value).build();
    }
    private static void await(CountDownLatch latch) {
        try { latch.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
    private static void awaitTerminal(McpTask task) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!task.isTerminal() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(task.isTerminal(), task.toSummary());
    }
}
