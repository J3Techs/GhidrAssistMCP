package ghidrassistmcp;

import java.util.function.Supplier;

/** Optional, synchronous request progress. Never inherited by background task workers. */
public final class McpRequestContext {
    @FunctionalInterface
    public interface ProgressReporter {
        void report(double progress, Double total, String message);
    }

    private static final ThreadLocal<State> CURRENT = new ThreadLocal<>();
    private McpRequestContext() {}

    private static final class State {
        private ProgressReporter reporter;
        private double last = Double.NEGATIVE_INFINITY;
        private State(ProgressReporter reporter) { this.reporter = reporter; }
    }

    public static <T> T callWithProgress(ProgressReporter reporter, Supplier<T> operation) {
        State previous = CURRENT.get();
        CURRENT.set(new State(reporter));
        try { return operation.get(); }
        finally {
            if (previous == null) CURRENT.remove(); else CURRENT.set(previous);
        }
    }

    public static boolean hasProgressReporter() {
        State state = CURRENT.get();
        return state != null && state.reporter != null;
    }

    /** Drop duplicate/invalid progress and stop reporting after transport failure. */
    public static void reportProgress(double progress, Double total, String message) {
        State state = CURRENT.get();
        if (state == null || state.reporter == null || !Double.isFinite(progress) || progress < 0
                || progress <= state.last || (total != null && (!Double.isFinite(total) || total < progress))) return;
        state.last = progress;
        try { state.reporter.report(progress, total, message); }
        catch (RuntimeException e) {
            // Progress is optional. Losing its stream must not change execution/cancellation semantics.
            state.reporter = null;
        }
    }
}
