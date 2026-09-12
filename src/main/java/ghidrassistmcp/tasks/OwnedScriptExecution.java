package ghidrassistmcp.tasks;

import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;
import ghidra.util.task.TaskMonitor;

/** A caller retains its locks/consumers until the actual script runner has exited. */
public final class OwnedScriptExecution {
    @FunctionalInterface public interface Operation { void run() throws Exception; }
    private OwnedScriptExecution() {}

    public static void run(Operation operation, TaskMonitor monitor, Duration timeout, McpTask task,
            boolean onEdt) throws Exception {
        run(operation, monitor, timeout, task, onEdt, SwingUtilities::invokeLater);
    }

    static void run(Operation operation, TaskMonitor monitor, Duration timeout, McpTask task,
            boolean onEdt, Consumer<Runnable> dispatch) throws Exception {
        if (onEdt && SwingUtilities.isEventDispatchThread())
            throw new IllegalStateException("Script execution must be initiated outside the EDT");
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean cancellation = new AtomicBoolean();
        AtomicBoolean finished = new AtomicBoolean();
        Thread owner = Thread.currentThread();
        boolean initiallyInterrupted = Thread.interrupted();
        Runnable cancel = () -> {
            synchronized (finished) {
            if (finished.get()) return;
            cancellation.set(true); monitor.cancel();
            if (task != null) task.requestCancellation();
            // Never interrupt Swing's shared event-dispatch thread.
            if (!onEdt) owner.interrupt();
            }
        };
        var timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MCP-Script-Cancellation"); t.setDaemon(true); return t;
        });
        Runnable runner = () -> {
            try { monitor.checkCancelled(); operation.run(); }
            catch (Throwable e) { failure.set(e); }
            finally { synchronized (finished) { finished.set(true); } done.countDown(); }
        };
        boolean interrupted = initiallyInterrupted;
        try {
            if (initiallyInterrupted) cancel.run();
            if (!timeout.isZero()) timer.schedule(cancel, timeout.toNanos(), TimeUnit.NANOSECONDS);
            timer.scheduleWithFixedDelay(() -> {
                if (task != null && (task.getStatus() == McpTask.Status.CANCEL_REQUESTED || task.getStatus() == McpTask.Status.CANCELLED)) cancel.run();
            }, 10, 10, TimeUnit.MILLISECONDS);
            if (onEdt) dispatch.accept(runner); else runner.run();
            // Interruption is a cancellation request, never proof that the EDT runner stopped.
            while (done.getCount() != 0) {
                try { done.await(); }
                catch (InterruptedException e) { interrupted = true; cancel.run(); }
            }
        } finally {
            synchronized (finished) { finished.set(true); }
            timer.shutdownNow();
            interrupted |= Thread.interrupted();
            if (interrupted) Thread.currentThread().interrupt();
        }
        if (failure.get() instanceof Exception e) throw e;
        if (failure.get() instanceof Error e) throw e;
        if (cancellation.get()) throw new CancellationException("Script cancellation requested; runner has now stopped");
    }
}
