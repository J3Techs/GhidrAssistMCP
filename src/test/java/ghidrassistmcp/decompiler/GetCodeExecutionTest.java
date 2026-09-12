package ghidrassistmcp.decompiler;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.tasks.*;
import ghidrassistmcp.tools.GetCodeTool;
import io.modelcontextprotocol.spec.McpSchema;

class GetCodeExecutionTest {
    @Test void textAndPcodeHonorTimeoutAndTaskCancellation() {
        for (String format : new String[] {"decompiler", "pcode"}) {
            Fixture fixture = new Fixture();
            McpTask task = new McpTask("get_code", Map.of());
            fixture.decompiler.duringDecompile = () -> task.requestCancellation();
            assertThrows(CancellationException.class, () -> fixture.tool.execute(
                Map.of("function", "1000", "format", format, "timeout_seconds", 7), fixture.program, null, task));
            assertEquals(7, fixture.decompiler.timeout);
            assertNotSame(TaskMonitor.DUMMY, fixture.decompiler.monitor);
            assertTrue(fixture.decompiler.monitor.isCancelled());
            assertTrue(fixture.decompiler.disposed);
        }
    }

    @Test void nativeTimeoutAndFailureAreErrorsInBothTextFormats() {
        for (String format : new String[] {"decompiler", "pcode"}) {
            for (boolean timedOut : new boolean[] {true, false}) {
                Fixture fixture = new Fixture();
                fixture.decompiler.timedOut = timedOut;
                McpSchema.CallToolResult result = fixture.tool.execute(
                    Map.of("function", "1000", "format", format), fixture.program);
                assertEquals(Boolean.TRUE, result.isError());
                assertEquals(30, fixture.decompiler.timeout);
                assertTrue(fixture.decompiler.disposed);
            }
        }
    }

    @Test void invalidTimeoutsAreRejectedBeforeNativeWork() {
        for (Object timeout : new Object[] {0, -1, 301, 1.5, "7"}) {
            Fixture fixture = new Fixture();
            assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of("function", "1000", "format", "decompiler",
                "timeout_seconds", timeout), fixture.program).isError());
            assertNull(fixture.decompiler.monitor);
        }
    }

    @Test void validationAndInitializationFailuresAreErrors() {
        Fixture fixture = new Fixture();
        assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of(), null).isError());
        assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of(), fixture.program).isError());
        assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of("function", "1000"), fixture.program).isError());
        assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of("function", "1000", "format", "unknown"), fixture.program).isError());
        fixture.decompiler.open = false;
        assertEquals(Boolean.TRUE, fixture.tool.execute(Map.of("function", "1000", "format", "pcode"), fixture.program).isError());
    }

    @Test void genericTaskRecordsDecompilationFailureAsFailed() {
        Fixture fixture = new Fixture();
        McpTaskManager manager = new McpTaskManager();
        try {
            Map<String,Object> args = Map.of("function", "1000", "format", "decompiler");
            McpTask task = manager.submitTask("get_code", args,
                context -> fixture.tool.execute(args, fixture.program, null, context));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (!task.isTerminal() && System.nanoTime() < deadline) LockSupport.parkNanos(1_000_000);
            assertEquals(McpTask.Status.FAILED, task.getStatus());
            assertEquals(Boolean.TRUE, task.getResult().isError());
        } finally { manager.shutdown(); }
    }

    private static final class Fixture {
        final FakeDecompiler decompiler = new FakeDecompiler();
        final Program program;
        final GetCodeTool tool;
        Fixture() {
            Program[] holder = new Program[1];
            Function function = proxy(Function.class, (p, m, a) -> switch (m.getName()) {
                case "getProgram" -> holder[0];
                case "getName" -> "example";
                case "getEntryPoint" -> new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0).getAddress(0x1000);
                default -> null;
            });
            FunctionManager functions = proxy(FunctionManager.class, (p, m, a) -> function);
            AddressFactory addresses = new DefaultAddressFactory(new AddressSpace[] {
                new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0)});
            program = proxy(Program.class, (p, m, a) -> switch (m.getName()) {
                case "isClosed" -> false;
                case "getName" -> "fixture";
                case "getAddressFactory" -> addresses;
                case "getFunctionManager" -> functions;
                default -> null;
            });
            holder[0] = program;
            tool = new GetCodeTool(new DecompilerService(p -> null, (s, p) -> new DecompileOptions(), () -> decompiler));
        }
    }

    private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }

    private static final class FakeDecompiler extends DecompInterface {
        TaskMonitor monitor;
        int timeout;
        boolean disposed, timedOut, open = true;
        Runnable duringDecompile = () -> {};
        @Override public synchronized boolean setOptions(DecompileOptions options) { return true; }
        @Override public synchronized boolean openProgram(Program p) { return open; }
        @Override public synchronized void dispose() { disposed = true; }
        @Override public String getLastMessage() { return "fixture initialization failure"; }
        @Override public synchronized DecompileResults decompileFunction(Function f, int timeout, TaskMonitor monitor) {
            this.timeout = timeout;
            this.monitor = monitor;
            duringDecompile.run();
            return new DecompileResults(f, null, null, null, "fixture native failure", null,
                timedOut ? DecompileProcess.DisposeState.DISPOSED_ON_TIMEOUT : DecompileProcess.DisposeState.NOT_DISPOSED);
        }
    }
}
