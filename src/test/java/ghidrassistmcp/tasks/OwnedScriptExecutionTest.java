package ghidrassistmcp.tasks;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.swing.SwingUtilities;
import ghidra.util.task.TaskMonitorAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class OwnedScriptExecutionTest {
    @Test void cancellationCallbackCannotOutliveTheOwningCall() throws Exception {
        var cancelling = new CountDownLatch(1); var releaseCallback = new CountDownLatch(1);
        var releaseOperation = new CountDownLatch(1);
        var monitor = new TaskMonitorAdapter(true) {
            @Override public void cancel() { super.cancel(); cancelling.countDown(); awaitIgnoringInterrupt(releaseCallback); }
        };
        try (var executor = Executors.newSingleThreadExecutor()) {
            var caller = executor.submit(() -> assertThrows(CancellationException.class, () ->
                OwnedScriptExecution.run(() -> awaitIgnoringInterrupt(releaseOperation), monitor, Duration.ofMillis(30), null, false)));
            try {
                assertTrue(cancelling.await(2, TimeUnit.SECONDS)); releaseOperation.countDown();
                assertThrows(TimeoutException.class, () -> caller.get(50, TimeUnit.MILLISECONDS),
                    "The owner cannot return while a cancellation callback could still interrupt it");
            } finally { releaseOperation.countDown(); releaseCallback.countDown(); }
            caller.get(2, TimeUnit.SECONDS);
        }
    }

    static final class Monitor extends TaskMonitorAdapter {
        final CountDownLatch cancelled = new CountDownLatch(1);
        Monitor() { super(true); }
        @Override public void cancel() { super.cancel(); cancelled.countDown(); }
    }
    static void awaitIgnoringInterrupt(CountDownLatch latch) {
        for (;;) try { latch.await(); return; } catch (InterruptedException ignored) { }
    }

    @Test void offEdtDeadlineCancelsMonitorButRetainsRunnerUntilExit() throws Exception {
        var monitor = new Monitor();
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var task = new McpTask("script", java.util.Map.of()); task.beginExecution();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var caller = executor.submit(() -> {
                assertThrows(CancellationException.class, () -> OwnedScriptExecution.run(() -> {
                    entered.countDown(); awaitIgnoringInterrupt(release);
                }, monitor, Duration.ofMillis(50), task, false));
            });
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                assertTrue(monitor.cancelled.await(2, TimeUnit.SECONDS));
                assertEquals(McpTask.Status.CANCEL_REQUESTED, task.getStatus());
                assertFalse(caller.isDone(), "A deadline cannot release the owning caller before runner exit");
            } finally { release.countDown(); }
            caller.get(2, TimeUnit.SECONDS);
        }
    }

    @Test void cancelledQueuedEdtDispatchCannotStartTheOperation() throws Exception {
        var monitor = new Monitor(); var scheduled = new CompletableFuture<Runnable>();
        var invoked = new AtomicBoolean();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var caller = executor.submit(() -> assertThrows(Exception.class, () ->
                OwnedScriptExecution.run(() -> invoked.set(true), monitor, Duration.ofMillis(30),
                    null, true, scheduled::complete)));
            try {
                var runner = scheduled.get(2, TimeUnit.SECONDS);
                assertTrue(monitor.cancelled.await(2, TimeUnit.SECONDS));
                assertFalse(caller.isDone());
                runner.run();
            } finally { if (!caller.isDone()) scheduled.getNow(() -> {}).run(); }
            caller.get(2, TimeUnit.SECONDS);
            assertFalse(invoked.get());
        }
    }

    @Test void interruptedCallerWaitsForActualSwingRunnerAndPreservesInterrupt() throws Exception {
        var monitor = new Monitor(); var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var failure = new AtomicReference<Throwable>(); var preserved = new AtomicBoolean();
        Thread caller = new Thread(() -> {
            try { OwnedScriptExecution.run(() -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                entered.countDown(); awaitIgnoringInterrupt(release);
            }, monitor, Duration.ZERO, null, true); }
            catch (Throwable e) { failure.set(e); }
            finally { preserved.set(Thread.currentThread().isInterrupted()); }
        });
        caller.start();
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS)); caller.interrupt();
            assertTrue(monitor.cancelled.await(2, TimeUnit.SECONDS));
            assertTrue(caller.isAlive());
        } finally { release.countDown(); caller.join(2000); }
        assertFalse(caller.isAlive()); assertInstanceOf(CancellationException.class, failure.get());
        assertTrue(preserved.get());
        SwingUtilities.invokeAndWait(() -> assertFalse(Thread.currentThread().isInterrupted()));
    }

    @Test void setupFailureOnDispatchedRunnerAlwaysSettlesCaller() throws Exception {
        var failure = new IllegalStateException("transaction setup failed");
        assertSame(failure, assertThrows(IllegalStateException.class, () ->
            OwnedScriptExecution.run(() -> { throw failure; }, new Monitor(), Duration.ZERO,
                null, true, Runnable::run)));
    }
}
