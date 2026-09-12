package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Regression coverage for mixed action tools and their execution traits. */
class ActionAwareDispatchTest {

    @Test
    void readActionBypassesWriterGuardWhileWriteActionWaits() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        backend.setAsyncExecutionEnabled(false);
        CountDownLatch writeEntered = new CountDownLatch(1);
        CountDownLatch releaseWrite = new CountDownLatch(1);
        ActionTool tool = new ActionTool(writeEntered, releaseWrite);
        backend.registerTool(tool);
        backend.registerTool(new ToolAlias("action_fixture_alias", tool));

        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<McpSchema.CallToolResult> write = executor.submit(
                () -> backend.callTool("action_fixture", Map.of("action", "write")));
            assertTrue(writeEntered.await(2, TimeUnit.SECONDS));

            Future<McpSchema.CallToolResult> read = executor.submit(
                () -> backend.callTool("action_fixture_alias", Map.of("action", "read")));
            assertEquals("read", text(read.get(2, TimeUnit.SECONDS)),
                "a verified read action must not wait for the mutation guard");
            assertFalse(write.isDone(), "the write should still own the guard");

            releaseWrite.countDown();
            assertEquals("write", text(write.get(2, TimeUnit.SECONDS)));
        } finally {
            releaseWrite.countDown();
            backend.shutdownWorkers();
        }
    }

    @Test
    void aliasesAndInvalidActionsRemainConservative() {
        ActionTool tool = new ActionTool(new CountDownLatch(0), new CountDownLatch(0));
        ToolAlias alias = new ToolAlias("alias", tool);

        assertFalse(tool.isReadOnly(), "catalog annotation remains conservative");
        assertTrue(tool.isReadOnly(Map.of("action", "read")));
        assertTrue(alias.isReadOnly(Map.of("action", "read")));
        assertFalse(tool.isReadOnly(Map.of("action", "unknown")));
        assertFalse(alias.isReadOnly(Map.of("action", "unknown")));
        assertTrue(tool.isLongRunning());
        assertTrue(alias.isLongRunning(Map.of("action", "write")));
    }

    private static String text(McpSchema.CallToolResult result) {
        String text = ((McpSchema.TextContent) result.content().get(0)).text(); return text.startsWith("[Context]") ? text.substring(text.indexOf("\n\n") + 2) : text;
    }

    private static final class ActionTool implements McpTool {
        private final CountDownLatch entered;
        private final CountDownLatch release;

        ActionTool(CountDownLatch entered, CountDownLatch release) {
            this.entered = entered;
            this.release = release;
        }

        @Override public String getName() { return "action_fixture"; }
        @Override public String getDescription() { return "action dispatch fixture"; }
        @Override public McpSchema.JsonSchema getInputSchema() {
            return new McpSchema.JsonSchema("object", Map.of(
                "action", Map.of("type", "string", "enum", List.of("read", "write"))),
                List.of("action"), false, null, null);
        }
        @Override public boolean isReadOnly() { return false; }
        @Override public boolean isLongRunning() { return true; }
        @Override public boolean isReadOnly(Map<String, Object> arguments) {
            return arguments.get("action") instanceof String action && "read".equalsIgnoreCase(action);
        }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
            if ("write".equalsIgnoreCase(String.valueOf(arguments.get("action")))) {
                entered.countDown();
                try { release.await(2, TimeUnit.SECONDS); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            return McpSchema.CallToolResult.builder()
                .addTextContent(String.valueOf(arguments.get("action"))).build();
        }
    }
}
