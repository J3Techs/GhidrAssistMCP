package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.swing.SwingUtilities;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class LifecycleShutdownTest {
    @Test void promptCallbackAndResourceReadRetainProgramUntilActualReturn() throws Exception {
        for (boolean resourceRead : List.of(false, true)) {
            var fixture = new ProgramOwnershipFixture();
            var backend = new GhidrAssistMCPHeadlessServer.HeadlessBackend(fixture.program);
            var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
            backend.getResourceRegistry().registerResource(new ghidrassistmcp.resources.McpResource() {
                public String getUriPattern() { return "ghidra://ownership-fixture"; }
                public String getName() { return "ownership fixture"; }
                public String getDescription() { return "test"; }
                public String getMimeType() { return "text/plain"; }
                public boolean canHandle(String uri) { return getUriPattern().equals(uri); }
                public Map<String,String> extractParams(String uri) { return Map.of(); }
                public String readContent(Program program, Map<String,String> params) {
                    entered.countDown(); awaitIgnoringInterrupt(release); return program.getName();
                }
            });
            try (var executor = Executors.newFixedThreadPool(2)) {
                var request = executor.submit(() -> resourceRead ? backend.readResource("ghidra://ownership-fixture")
                    : backend.withProgramRequest(program -> { entered.countDown(); awaitIgnoringInterrupt(release); return program.getName(); }));
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                backend.beginShutdown(); var drain = executor.submit(backend::shutdown);
                try {
                    assertEquals(2, fixture.consumers.size()); assertFalse(drain.isDone());
                    assertThrows(IllegalStateException.class, () -> backend.withProgramRequest(Program::getName));
                    assertThrows(IllegalStateException.class, () -> backend.readResource("ghidra://ownership-fixture"));
                } finally { release.countDown(); }
                assertEquals("lifecycle-fixture", request.get(2, TimeUnit.SECONDS));
                drain.get(2, TimeUnit.SECONDS); assertTrue(fixture.consumers.isEmpty());
            } finally { release.countDown(); backend.shutdown(); }
        }
    }

    @Test void noProjectHeadlessShutdownDrainsBsimBeforeReleasingItsProgram(@org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary) throws Exception {
        var runtime = new ghidrassistmcp.bsim.BsimRuntime(temporary);
        var singleton = ghidrassistmcp.bsim.BsimRuntime.class.getDeclaredField("instance"); singleton.setAccessible(true);
        assertNull(singleton.get(null)); singleton.set(null, runtime);
        var fixture = new ProgramOwnershipFixture();
        var backend = new GhidrAssistMCPHeadlessServer.HeadlessBackend(fixture.program);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var cancelled = new CountDownLatch(1);
        var operation = ghidrassistmcp.bsim.BsimOperation.of("ownership_fixture", "test", Map.of(), List.of(), true, false, false,
            (context, args, monitor) -> { monitor.addCancelledListener(cancelled::countDown); entered.countDown(); awaitIgnoringInterrupt(release); return Map.of(); });
        try (var executor = Executors.newFixedThreadPool(2)) {
            var work = executor.submit(() -> runtime.execute(operation, Map.of(), fixture.program, backend));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            var drain = executor.submit(backend::shutdown);
            try {
                assertTrue(cancelled.await(2, TimeUnit.SECONDS)); assertFalse(drain.isDone());
                assertNull(backend.getProject()); assertSame(fixture.program, backend.getCurrentProgram());
                assertFalse(fixture.consumers.isEmpty());
            } finally { release.countDown(); }
            assertThrows(ExecutionException.class, () -> work.get(2, TimeUnit.SECONDS));
            drain.get(2, TimeUnit.SECONDS); assertTrue(fixture.consumers.isEmpty());
            assertEquals("TERMINATED", runtime.lifecycleState()); assertNull(singleton.get(null));
        } finally { release.countDown(); runtime.close(); backend.shutdown(); }
    }

    static void awaitIgnoringInterrupt(CountDownLatch latch) {
        for (;;) try { latch.await(); return; } catch (InterruptedException ignored) { }
    }
    static McpTool blockingTool(CountDownLatch entered, CountDownLatch release) {
        return new McpTool() {
            public String getName() { return "lifecycle_fixture"; }
            public String getDescription() { return "Test ownership"; }
            public McpSchema.JsonSchema getInputSchema() { return new McpSchema.JsonSchema("object", Map.of(), List.of(), false, null, null); }
            public McpSchema.CallToolResult execute(Map<String,Object> args, Program program) {
                entered.countDown(); awaitIgnoringInterrupt(release);
                return McpSchema.CallToolResult.builder().addTextContent("settled").build();
            }
        };
    }

    @Test void synchronousRequestAndHeadlessOwnershipSurviveShutdownUntilWorkerStops() throws Exception {
        var fixture = new ProgramOwnershipFixture();
        var backend = new GhidrAssistMCPHeadlessServer.HeadlessBackend(fixture.program);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        backend.registerTool(blockingTool(entered, release));
        try (var executor = Executors.newFixedThreadPool(2)) {
            var request = executor.submit(() -> backend.callTool("lifecycle_fixture", Map.of()));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals(2, fixture.consumers.size(), "headless owner plus active request");
            backend.beginShutdown();
            var drain = executor.submit(backend::shutdown);
            try {
                assertTrue(Boolean.TRUE.equals(backend.callTool("lifecycle_fixture", Map.of()).isError()));
                assertThrows(IllegalStateException.class, () -> backend.setProgram(null));
                assertThrows(IllegalStateException.class, () -> backend.submitTask("late", Map.of(), fixture.program, task -> null));
                assertFalse(drain.isDone()); assertEquals(2, fixture.consumers.size());
            } finally { release.countDown(); }
            request.get(2, TimeUnit.SECONDS); drain.get(2, TimeUnit.SECONDS);
            assertTrue(fixture.consumers.isEmpty()); assertNull(backend.getCurrentProgram());
        } finally { release.countDown(); backend.shutdown(); }
    }

    @Test void guiDrainRunsOutsideEdtAndManagerMonitorAndRejectsReopenUntilSettled() throws Exception {
        var draining = new CountDownLatch(1); var release = new CountDownLatch(1);
        var managerRef = new AtomicReference<GhidrAssistMCPManager>();
        var failure = new AtomicReference<Throwable>();
        var backend = new GhidrAssistMCPBackend() {
            @Override public void shutdownWorkers() {
                try {
                    assertFalse(SwingUtilities.isEventDispatchThread());
                    assertFalse(Thread.holdsLock(managerRef.get()));
                    SwingUtilities.invokeAndWait(() -> { synchronized (managerRef.get()) { draining.countDown(); } });
                    awaitIgnoringInterrupt(release);
                } catch (Throwable e) { failure.set(e); }
                super.shutdownWorkers();
            }
        };
        var manager = new GhidrAssistMCPManager(backend); managerRef.set(manager);
        try {
            SwingUtilities.invokeAndWait(manager::shutdownIfUnused);
            assertTrue(draining.await(2, TimeUnit.SECONDS));
            assertTrue(manager.isStopping()); assertFalse(manager.termination().isDone());
            assertNull(manager.getActiveTool()); assertNull(manager.getActivePlugin());
            assertThrows(IllegalStateException.class, () -> manager.registerTool(null, null));
            manager.shutdownIfUnused(); // repeat close must not start another drain
        } finally { release.countDown(); }
        manager.termination().get(2, TimeUnit.SECONDS); assertNull(failure.get());
    }
}
