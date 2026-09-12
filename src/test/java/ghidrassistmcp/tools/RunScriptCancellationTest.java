package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.*;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.tasks.*;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class RunScriptCancellationTest {
    @Test void asynchronousScriptCancellationSettlesCancelledAfterRunnerStops() throws Exception {
        var manager = new McpTaskManager(1);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var cancelled = new CountDownLatch(1); var cleaned = new CountDownLatch(1);
        var monitor = new TaskMonitorAdapter(true) {
            @Override public void cancel() { super.cancel(); cancelled.countDown(); }
        };
        try {
            var task = manager.submitTask("run_script", Map.of(), McpProgramContext.empty(), current -> {
                try {
                    OwnedScriptExecution.run(() -> {
                        entered.countDown();
                        for (;;) try { release.await(); break; } catch (InterruptedException ignored) { }
                    }, monitor, Duration.ZERO, current, false);
                    return McpSchema.CallToolResult.builder().addTextContent("completed").build();
                } catch (Exception failure) {
                    RunScriptTool.propagateTaskCancellation(current, monitor, failure);
                    return McpSchema.CallToolResult.builder().isError(true).addTextContent("script failed").build();
                }
            }, cleaned::countDown);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertTrue(manager.cancelTask(task.getTaskId()));
            assertTrue(cancelled.await(2, TimeUnit.SECONDS));
            assertEquals(McpTask.Status.CANCEL_REQUESTED, task.getStatus());
            assertEquals(1, cleaned.getCount(), "Cancellation must retain ownership while the actual script runs");
            release.countDown();
            assertTrue(cleaned.await(2, TimeUnit.SECONDS));
            assertEquals(McpTask.Status.CANCELLED, task.getStatus());
        } finally { release.countDown(); manager.shutdown(); }
    }

    @Test void synchronousCancellationAndOrdinaryAsyncErrorsKeepTheirReports() {
        var monitor = new TaskMonitorAdapter(true);
        var failure = new IllegalStateException("script failure");
        assertDoesNotThrow(() -> RunScriptTool.propagateTaskCancellation(new McpTask("run_script", Map.of()), monitor, failure));
        monitor.cancel();
        assertDoesNotThrow(() -> RunScriptTool.propagateTaskCancellation(null, monitor, failure));
    }
}
