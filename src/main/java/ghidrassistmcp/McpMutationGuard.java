package ghidrassistmcp;

import java.util.concurrent.locks.ReentrantLock;

/** Serialize MCP writers, including multi-program native operations. Native UI locks still apply. */
public final class McpMutationGuard {
    public static final ReentrantLock LOCK = new ReentrantLock(true);
    private McpMutationGuard() {}

    /**
     * Run best-effort verification after commit without excluding other MCP writers.
     * The caller retains the program and checks revisions; its outer guard scope is restored.
     */
    public static <T> T afterCommit(ghidra.program.model.listing.Program program,
            java.util.function.Supplier<T> verification) {
        if (program.getCurrentTransactionInfo() != null)
            throw new IllegalStateException("Post-mutation verification requires a settled transaction");
        int holds = LOCK.getHoldCount();
        for (int i = 0; i < holds; i++) LOCK.unlock();
        try { return verification.get(); }
        finally {
            // Restore the enclosing scope even when cancellation interrupts verification.
            for (int i = 0; i < holds; i++) LOCK.lock();
        }
    }
}
