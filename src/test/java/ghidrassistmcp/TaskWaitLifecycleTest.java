package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskManager;
import io.modelcontextprotocol.spec.McpSchema;

class TaskWaitLifecycleTest {
    @Test void timeoutDoesNotCancelOperationAndTerminalPayloadRemainsAvailable() throws Exception {
        McpTaskManager manager = new McpTaskManager(1);
        CountDownLatch release = new CountDownLatch(1), started = new CountDownLatch(1);
        try {
            McpSchema.CallToolResult payload = result("x".repeat(100_000));
            McpTask task = manager.submitTask("slow", Map.of(), ignored -> {
                started.countDown(); await(release); return payload;
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            Map<String, Object> snapshot = manager.waitForTask(task.getTaskId(), 20, null);
            assertEquals("timeout", snapshot.get("wait_outcome"));
            assertEquals("RUNNING", snapshot.get("status"));
            assertFalse(task.isTerminal());
            release.countDown();
            snapshot = manager.waitForTask(task.getTaskId(), 2000, null);
            assertEquals("terminal", snapshot.get("wait_outcome"));
            assertEquals(true, snapshot.get("result_available"));
            assertFalse(snapshot.toString().contains("xxx"));
            assertSame(payload, manager.getTaskResult(task.getTaskId()));
        } finally { release.countDown(); manager.shutdown(); }
    }

    @Test void progressVersionWakesWaitersAndUnchangedUpdatesDoNotAdvanceCursor() throws Exception {
        McpTask task = new McpTask("query", Map.of());
        task.markStarted();
        long version = task.getStateVersion();
        final long waitVersion = version;
        AtomicReference<Map<String, Object>> observed = new AtomicReference<>();
        Thread waiter = new Thread(() -> {
            try { observed.set(task.awaitSnapshot(2000, waitVersion)); }
            catch (InterruptedException e) { throw new AssertionError(e); }
        });
        waiter.start();
        task.updateProgress(50, "halfway");
        waiter.join(2500);
        assertFalse(waiter.isAlive());
        assertEquals("changed", observed.get().get("wait_outcome"));
        assertTrue(task.getStateVersion() > version);
        version = task.getStateVersion();
        task.updateProgress(50, "halfway");
        assertEquals(version, task.getStateVersion());
        assertThrows(IllegalArgumentException.class, () -> task.awaitSnapshot(0, task.getStateVersion() + 1));
        task.markCompleted(result("ok"));
        assertEquals("terminal", task.awaitSnapshot(0, task.getStateVersion()).get("wait_outcome"));
    }

    @Test void interruptedWaiterLeavesOperationRunning() throws Exception {
        McpTask task = new McpTask("query", Map.of()); task.markStarted();
        CountDownLatch entered = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread waiter = new Thread(() -> {
            entered.countDown();
            try { task.awaitSnapshot(30000, null); }
            catch (InterruptedException expected) { failure.set(expected); }
        });
        waiter.start(); assertTrue(entered.await(1, TimeUnit.SECONDS));
        waiter.interrupt(); waiter.join(2000);
        assertInstanceOf(InterruptedException.class, failure.get());
        assertEquals(McpTask.Status.RUNNING, task.getStatus());
    }

    @Test void nullResultFailsAndErrorResultsRetainLegacyContract() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            McpTask task = backend.getTaskManager().submitTask("broken", Map.of(), ignored -> null);
            backend.getTaskManager().waitForTask(task.getTaskId(), 2000, null);
            assertEquals(McpTask.Status.FAILED, task.getStatus());
            assertTrue(backend.callTool("get_task_status", Map.of("task_id", task.getTaskId())).isError());
            var payload = McpSchema.CallToolResult.builder().isError(true).structuredContent(Map.of("reason", "busy"))
                .addTextContent("busy").build();
            McpTask errorTask = backend.getTaskManager().submitTask("error", Map.of(), ignored -> payload);
            backend.getTaskManager().waitForTask(errorTask.getTaskId(), 2000, null);
            var observed = backend.callTool("get_task_status", Map.of("task_id", errorTask.getTaskId()));
            assertTrue(observed.isError()); assertEquals(payload.structuredContent(), observed.structuredContent());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void waitToolRejectsInvalidBudgetsAndReturnsStructuredMetadata() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            McpTask task = backend.getTaskManager().submitTask("done", Map.of(), ignored -> result("ok"));
            var success = backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", 2000));
            assertNotEquals(Boolean.TRUE, success.isError());
            assertEquals("terminal", ((Map<?, ?>) success.structuredContent()).get("wait_outcome"));
            for (Object invalid : List.of(-1, 30001, 0.5, "1", Double.NaN)) {
                assertTrue(backend.callTool("wait_task", Map.of("task_id", task.getTaskId(), "timeout_ms", invalid)).isError());
            }
            assertTrue(backend.callTool("wait_task", Map.of("task_id", "missing")).isError());
            assertTrue(backend.callTool("get_task_status", Map.of("task_id", "missing")).isError());
            assertTrue(backend.callTool("cancel_task", Map.of("task_id", "missing")).isError());
            assertNotNull(backend.getAvailableTools().stream().filter(t -> t.name().equals("wait_task")).findFirst().orElseThrow().outputSchema());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void cancelToolCanInterruptWorkerHoldingMutationGuard() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            backend.registerTool(new McpTool() {
                public String getName() { return "mutating_fixture"; }
                public String getDescription() { return "Fixture"; }
                public McpSchema.JsonSchema getInputSchema() { return new McpSchema.JsonSchema("object", Map.of(), List.of(), null, null, null); }
                public boolean isLongRunning() { return true; }
                public boolean isReadOnly() { return false; }
                public McpSchema.CallToolResult execute(Map<String, Object> args, Program p) {
                    started.countDown(); await(release); return result("ok");
                }
            });
            backend.callTool("mutating_fixture", Map.of());
            assertTrue(started.await(2, TimeUnit.SECONDS));
            McpTask task = backend.getTaskManager().listTasks(null).getFirst();
            var response = assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),
                () -> backend.callTool("cancel_task", Map.of("task_id", task.getTaskId())));
            assertNotEquals(Boolean.TRUE, response.isError());
            assertTrue(((McpSchema.TextContent) response.content().getFirst()).text().contains("Cancellation requested"));
            backend.getTaskManager().waitForTask(task.getTaskId(), 2000, null);
            assertEquals(McpTask.Status.CANCELLED, task.getStatus());
        } finally { release.countDown(); backend.getTaskManager().shutdown(); }
    }

    @Test void programSnapshotsDistinguishVersionsAndManagersHaveSeparateIdentity() {
        var first = new McpProgramContext("same", "/same", "file", "project/same#version=1");
        var second = new McpProgramContext("same", "/same", "file", "project/same#version=2");
        assertFalse(first.identifiesSameProgram(second));
        var task = new McpTask("query", Map.of(), first);
        assertEquals(first.programId(), ((Map<?, ?>) task.snapshot().get("program")).get("program_id"));
        McpTaskManager left = new McpTaskManager(), right = new McpTaskManager();
        try { assertNotEquals(left.getInstanceId(), right.getInstanceId()); }
        finally { left.shutdown(); right.shutdown(); }
    }

    @Test void listingIsBoundedAndFullTaskIdsCanBeRetrieved() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            for (int i = 0; i < 4; i++) {
                var task = backend.getTaskManager().submitTask("done", Map.of(), ignored -> result("ok"));
                backend.getTaskManager().waitForTask(task.getTaskId(), 2000, null);
            }
            var data = (Map<?, ?>) backend.callTool("list_tasks", Map.of("status", "COMPLETED", "limit", 2)).structuredContent();
            assertEquals(4, data.get("total")); assertEquals(2, data.get("returned"));
            assertEquals(2, data.get("omitted")); assertEquals(2, data.get("next_offset"));
            var items = (List<?>) data.get("tasks");
            for (Object item : items) assertNotNull(backend.getTaskManager().getTask((String) ((Map<?, ?>) item).get("task_id")));
            assertTrue(backend.callTool("list_tasks", Map.of("limit", 101)).isError());
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void metadataStringsAreBoundedAndArgumentsAreDeeplySnapshotted() {
        var nested = new java.util.ArrayList<>(List.of("original"));
        var args = new java.util.HashMap<String, Object>(); args.put("nested", nested);
        McpTask task = new McpTask("query", args);
        nested.set(0, "changed"); args.put("other", true);
        assertEquals(List.of("original"), task.getArguments().get("nested"));
        assertFalse(task.getArguments().containsKey("other"));
        assertThrows(UnsupportedOperationException.class, () -> task.getArguments().put("x", true));
        task.markStarted(); task.updateProgress(1, "x".repeat(10000));
        assertEquals(2048, ((String) task.snapshot().get("progress_message")).length());
        assertEquals(true, task.snapshot().get("metadata_truncated"));
    }

    @Test void asyncWorkerExecutesTheArgumentSnapshot() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            backend.registerTool(new McpTool() {
                public String getName() { return "argument_fixture"; }
                public String getDescription() { return "Fixture"; }
                public McpSchema.JsonSchema getInputSchema() { return new McpSchema.JsonSchema("object", Map.of(), List.of(), null, null, null); }
                public boolean isLongRunning() { return true; }
                public McpSchema.CallToolResult execute(Map<String, Object> args, Program p) {
                    entered.countDown(); await(release);
                    return result(((List<?>) args.get("values")).getFirst().toString());
                }
            });
            var values = new java.util.ArrayList<>(List.of("original"));
            var args = new java.util.HashMap<String, Object>(); args.put("values", values);
            backend.callTool("argument_fixture", args);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            values.set(0, "mutated");
            release.countDown();
            McpTask task = backend.getTaskManager().listTasks(null).getFirst();
            backend.getTaskManager().waitForTask(task.getTaskId(), 2000, null);
            assertEquals("original", ((McpSchema.TextContent) task.getResult().content().getFirst()).text());
        } finally { release.countDown(); backend.getTaskManager().shutdown(); }
    }

    private static McpSchema.CallToolResult result(String text) {
        return McpSchema.CallToolResult.builder().addTextContent(text).build();
    }
    private static void await(CountDownLatch latch) {
        try { latch.await(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
    }
}
