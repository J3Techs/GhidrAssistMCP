package ghidrassistmcp.tools;

import java.util.LinkedHashSet;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.ProgramIdentity;

/** Exact target selection for tools with source_program/target_program arguments. */
public final class ProgramSelection {
    private ProgramSelection() {}
    public static Program resolve(GhidrAssistMCPBackend backend, String selector, Program current) {
        var programs = new LinkedHashSet<Program>();
        if (backend != null) programs.addAll(backend.getAllOpenPrograms());
        if (current != null) programs.add(current);
        return ProgramIdentity.resolve(selector, programs);
    }
    /** Retain only the explicitly selected database for the duration of actual execution. */
    public static Lease lease(GhidrAssistMCPBackend backend, String selector, Program current) {
        return new Lease(resolve(backend, selector, current));
    }
    public static final class Lease implements AutoCloseable {
        private final Object consumer = new Object();
        private final Program program;
        private boolean closed;
        private Lease(Program program) {
            this.program = program;
            if (!program.addConsumer(consumer)) throw new IllegalArgumentException("Selected program closed before execution");
        }
        public Program program() { return program; }
        @Override public synchronized void close() {
            if (closed) return;
            closed = true;
            if (!program.isClosed() && program.isUsedBy(consumer)) program.release(consumer);
        }
    }
}
