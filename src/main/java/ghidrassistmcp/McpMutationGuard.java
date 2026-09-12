package ghidrassistmcp;

import java.util.concurrent.locks.ReentrantLock;

/** Serialize MCP writers, including multi-program native operations. Native UI locks still apply. */
public final class McpMutationGuard {
    public static final ReentrantLock LOCK = new ReentrantLock(true);
    private McpMutationGuard() {}
}
