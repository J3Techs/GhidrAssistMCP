package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tools.CancelTaskTool;
import ghidrassistmcp.tools.ListTasksTool;
import ghidrassistmcp.tools.WaitTaskTool;
import io.modelcontextprotocol.json.schema.jackson2.DefaultJsonSchemaValidator;
import io.modelcontextprotocol.spec.McpSchema;

class TaskToolSchemaContractTest {
    private final DefaultJsonSchemaValidator validator = new DefaultJsonSchemaValidator();
    private final ObjectMapper json = new ObjectMapper();

    @Test void declaredSchemasValidateRealSuccessResultsAndJsonTextFallbacks() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            for (McpTool tool : List.of(new ListTasksTool(), new CancelTaskTool(), new WaitTaskTool()))
                assertTrue(validator.validateSchema(tool.getOutputSchema()).valid(), tool.getName());
            McpTask task = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> {
                started.countDown(); await(release); return payload();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            validate(new WaitTaskTool(), backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 0)), false);
            validate(new ListTasksTool(), backend.callTool("list_tasks", Map.of("limit", 1)), false);
            validate(new CancelTaskTool(), backend.callTool("cancel_task", Map.of("task_id", task.getTaskId())), false);
            release.countDown();
            backend.getTaskManager().waitForTask(task.getTaskId(), 2000, null);
            validate(new WaitTaskTool(), backend.callTool("wait_task", Map.of("task_id", task.getTaskId())), false);
        } finally { release.countDown(); backend.getTaskManager().shutdown(); }
    }

    @Test void toolErrorsHaveStableTypedBranchesAndAreNotMalformedSuccesses() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            validateError(new WaitTaskTool(), backend.callTool("wait_task", Map.of("task_id", "missing")), "TASK_NOT_FOUND");
            validateError(new WaitTaskTool(), backend.callTool("wait_task", Map.of("task_id", "missing", "timeout_ms", 0.5)), "INVALID_ARGUMENT");
            validateError(new CancelTaskTool(), backend.callTool("cancel_task", Map.of("task_id", "missing")), "TASK_NOT_FOUND");
            validateError(new CancelTaskTool(), backend.callTool("cancel_task", Map.of()), "INVALID_ARGUMENT");
            validateError(new ListTasksTool(), backend.callTool("list_tasks", Map.of("limit", 101)), "INVALID_ARGUMENT");
            validateError(new ListTasksTool(), backend.callTool("list_tasks", Map.of("status", "invalid")), "INVALID_ARGUMENT");
            for (McpTool tool : List.of(new ListTasksTool(), new CancelTaskTool(), new WaitTaskTool())) {
                validateError(tool, tool.execute(Map.of(), null), "BACKEND_UNAVAILABLE");
                assertFalse(validator.validate(tool.getOutputSchema(), Map.of("schema_version", 1)).valid());
            }
            McpTask completed = backend.getTaskManager().submitTask("complete", Map.of(), ignored -> payload());
            backend.getTaskManager().waitForTask(completed.getTaskId(), 2000, null);
            validateError(new CancelTaskTool(), backend.callTool("cancel_task", Map.of("task_id", completed.getTaskId())), "CANCELLATION_NOT_ACCEPTED");
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void listContinuationSchemaAndTerminalPayloadCompatibilityAreRealContracts() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            McpSchema.CallToolResult original = payload();
            McpTask first = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> original);
            backend.getTaskManager().waitForTask(first.getTaskId(), 2000, null);
            McpTask second = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> payload());
            backend.getTaskManager().waitForTask(second.getTaskId(), 2000, null);
            var page = backend.callTool("list_tasks", Map.of("limit", 1));
            validate(new ListTasksTool(), page, false);
            Map<String, Object> broken = new java.util.LinkedHashMap<>((Map<String, Object>) page.structuredContent());
            assertEquals(true, broken.remove("has_more"));
            assertFalse(validator.validate(new ListTasksTool().getOutputSchema(), broken).valid());
            broken = new java.util.LinkedHashMap<>((Map<String, Object>) page.structuredContent());
            broken.remove("next_offset");
            assertFalse(validator.validate(new ListTasksTool().getOutputSchema(), broken).valid());
            validate(new ListTasksTool(), backend.callTool("list_tasks", Map.of("limit", 1, "offset", 1)), false);
            var legacy = backend.callTool("get_task_status", Map.of("task_id", first.getTaskId()));
            assertEquals(original.structuredContent(), legacy.structuredContent());
            assertEquals(original.content().size(), legacy.content().size());
            assertNull(new ghidrassistmcp.tools.GetTaskStatusTool().getOutputSchema());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void progressReportsActualWaitWithoutExtendingItsDeadlineOnWorkerUpdates() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        var updates = Executors.newSingleThreadScheduledExecutor();
        try {
            McpTask task = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> {
                started.countDown(); await(release); return payload();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            var sequence = new java.util.concurrent.atomic.AtomicInteger();
            updates.scheduleAtFixedRate(() -> task.updateProgress(sequence.incrementAndGet() % 10, "changing phase"), 0, 10, TimeUnit.MILLISECONDS);
            List<Double> progress = new ArrayList<>();
            List<Double> totals = new ArrayList<>();
            long before = System.nanoTime();
            var result = McpRequestContext.callWithProgress((value, total, message) -> {
                progress.add(value); totals.add(total);
            }, () -> backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 350)));
            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before);
            validate(new WaitTaskTool(), result, false);
            assertEquals("timeout", ((Map<?, ?>) result.structuredContent()).get("wait_outcome"));
            assertEquals(McpTask.Status.RUNNING, task.getStatus());
            assertTrue(elapsed >= 300 && elapsed < 2000, "caller deadline must not restart on task updates: " + elapsed);
            assertTrue(progress.size() >= 2 && progress.size() <= 4, progress.toString());
            for (int i = 1; i < progress.size(); i++) assertTrue(progress.get(i) > progress.get(i - 1));
            assertTrue(totals.stream().allMatch(total -> total == 0.350));
            assertFalse(McpRequestContext.hasProgressReporter());
        } finally { updates.shutdownNow(); release.countDown(); backend.getTaskManager().shutdown(); }
    }

    @Test void progressFollowingReturnsOnVersionChangeWithoutCancellingTheTask() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            McpTask task = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> {
                started.countDown(); await(release); return payload();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            long version = task.getStateVersion();
            var result = McpRequestContext.callWithProgress((value, total, message) -> {
                if (value == 0) task.updateProgress(25, "new phase");
            }, () -> backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 2000, "after_version", version)));
            validate(new WaitTaskTool(), result, false);
            assertEquals("changed", ((Map<?, ?>) result.structuredContent()).get("wait_outcome"));
            assertEquals(McpTask.Status.RUNNING, task.getStatus());
        } finally { release.countDown(); backend.getTaskManager().shutdown(); }
    }

    @Test void interruptedWaitIsSchemaValidAndDoesNotCancelTheOperation() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            McpTask task = backend.getTaskManager().submitTask("fixture", Map.of(), ignored -> {
                started.countDown(); await(release); return payload();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            Thread.currentThread().interrupt();
            var result = new WaitTaskTool().execute(Map.of("task_id", task.getTaskId(), "timeout_ms", 1000), null, backend);
            assertTrue(Thread.interrupted(), "wait must preserve caller interruption");
            validateError(new WaitTaskTool(), result, "WAIT_INTERRUPTED");
            assertEquals(McpTask.Status.RUNNING, task.getStatus());
        } finally { Thread.interrupted(); release.countDown(); backend.getTaskManager().shutdown(); }
    }

    private void validateError(McpTool tool, McpSchema.CallToolResult result, String code) throws Exception {
        validate(tool, result, true);
        var error = (Map<?, ?>) ((Map<?, ?>) result.structuredContent()).get("error");
        assertEquals(code, error.get("code"));
        assertInstanceOf(Boolean.class, error.get("retryable"));
    }

    private void validate(McpTool tool, McpSchema.CallToolResult result, boolean isError) throws Exception {
        assertEquals(isError, Boolean.TRUE.equals(result.isError()));
        var validation = validator.validate(tool.getOutputSchema(), result.structuredContent());
        assertTrue(validation.valid(), tool.getName() + ": " + validation.errorMessage());
        assertEquals(2, result.content().size(), "legacy text plus JSON compatibility text");
        var compatibility = ((McpSchema.TextContent) result.content().get(1)).text();
        assertEquals(json.readTree(json.writeValueAsString(result.structuredContent())), json.readTree(compatibility));
    }

    private static McpSchema.CallToolResult payload() {
        return McpSchema.CallToolResult.builder().addTextContent("result")
            .structuredContent(Map.of("original_payload", true)).build();
    }
    private static void await(CountDownLatch latch) {
        try { latch.await(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
    }
}
