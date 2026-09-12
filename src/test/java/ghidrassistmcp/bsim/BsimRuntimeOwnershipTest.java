package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import ghidrassistmcp.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(10)
class BsimRuntimeOwnershipTest {
    static void awaitIgnoringInterrupt(CountDownLatch latch) {
        for (;;) try { latch.await(); return; } catch (InterruptedException ignored) { }
    }
    static BsimOperation operation(CountDownLatch entered, CountDownLatch release) {
        return BsimOperation.of("ownership_fixture", "test", Map.of(), List.of(), true, false, false,
            (context, args, monitor) -> { entered.countDown(); awaitIgnoringInterrupt(release); return Map.of("settled", true); });
    }

    @Test void closeFailureRetainsProgramAndRetryCompletesAfterActualWorkerExit(@TempDir Path root) throws Exception {
        var runtime = new BsimRuntime(root); var fixture = new ProgramOwnershipFixture();
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var operation = operation(entered, release);
        try (var executor = Executors.newSingleThreadExecutor()) {
            var caller = executor.submit(() -> runtime.execute(operation, Map.of(), fixture.program, null));
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                assertThrows(IllegalStateException.class, () -> runtime.close(20));
                assertEquals("STOPPING", runtime.lifecycleState());
                assertFalse(fixture.consumers.isEmpty(), "Future.cancel is not actual worker completion");
                assertThrows(IllegalStateException.class, () -> runtime.execute(operation, Map.of(), null, null));
                assertThrows(ExecutionException.class, () -> caller.get(2, TimeUnit.SECONDS));
                assertFalse(fixture.consumers.isEmpty(), "Interrupted caller cannot release the worker's consumer");
            } finally { release.countDown(); runtime.close(2000); }
            assertEquals("TERMINATED", runtime.lifecycleState()); assertTrue(fixture.consumers.isEmpty());
        }
    }

    @Test void closingQueuedOwnerDoesNotCancelAnotherBackendAndReleasesQueuedConsumer(@TempDir Path root) throws Exception {
        var runtime = new BsimRuntime(root);
        var first = new GhidrAssistMCPBackend(); var second = new GhidrAssistMCPBackend();
        var firstEntered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var queuedEntered = new CountDownLatch(1); var queued = new ProgramOwnershipFixture();
        try (var executor = Executors.newFixedThreadPool(2)) {
            var active = executor.submit(() -> runtime.execute(operation(firstEntered, release), Map.of(), null, first));
            assertTrue(firstEntered.await(2, TimeUnit.SECONDS));
            var pending = executor.submit(() -> runtime.execute(operation(queuedEntered, new CountDownLatch(0)), Map.of(), queued.program, second));
            try {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                while (queued.consumers.isEmpty() && System.nanoTime() < deadline) Thread.sleep(1);
                assertFalse(queued.consumers.isEmpty(), "Queued work reserves its target before caller can exit");
                runtime.drainBackend(second, 2000);
                assertThrows(ExecutionException.class, () -> pending.get(2, TimeUnit.SECONDS));
                assertTrue(queued.consumers.isEmpty()); assertEquals(1, queuedEntered.getCount());
                assertEquals("RUNNING", runtime.lifecycleState()); assertFalse(active.isDone());
                assertThrows(IllegalStateException.class, () -> runtime.execute(operation(firstEntered, release), Map.of(), null, second));
            } finally { release.countDown(); }
            active.get(2, TimeUnit.SECONDS); runtime.drainBackend(first, 2000);
            assertEquals("TERMINATED", runtime.lifecycleState());
        } finally { release.countDown(); runtime.close(2000); first.getTaskManager().shutdown(); second.getTaskManager().shutdown(); }
    }
}
