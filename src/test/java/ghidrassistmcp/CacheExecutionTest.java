package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.cache.McpCache;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

class CacheExecutionTest {
    final AtomicLong revision = new AtomicLong();
    final Program target = program("target", revision);
    final Program windowA = program("window-a", new AtomicLong());
    final Program windowB = program("window-b", new AtomicLong());
    final Backend backend = new Backend();
    final Query tool = new Query();
    final Map<String,Object> args = Map.of("program_name", "target");

    CacheExecutionTest() { backend.registerTool(tool); }
    @AfterEach void close() { backend.getTaskManager().shutdown(); }

    @Test void syncCacheRefreshesWindowContextWithoutDuplicatingIt() {
        backend.setAsyncExecutionEnabled(false);
        backend.active = windowA;
        assertTrue(text(backend.callTool(tool.getName(), args)).contains("Active window: window-a"));
        backend.active = windowB;
        String hit = text(backend.callTool(tool.getName(), args));
        assertTrue(hit.contains("Operating on: target | Active window: window-b"));
        assertFalse(hit.contains("window-a"));
        assertEquals(1, hit.split("\\[Context\\]", -1).length - 1);
        assertEquals(1, tool.calls.get());
    }

    @Test void asyncSuccessWarmsCacheAndPreservesRawTaskResult() {
        backend.active = windowA;
        runAsync();
        McpTask task = backend.getTaskManager().listTasks(null).get(0);
        assertFalse(text(task.getResult()).contains("[Context]"));
        backend.active = windowB;
        McpSchema.CallToolResult hit = backend.callTool(tool.getName(), args);
        assertTrue(text(hit).contains("Active window: window-b"));
        assertFalse(text(hit).contains("Task submitted"));
        assertEquals(1, tool.calls.get());
        assertEquals(Map.of("value", 42), hit.structuredContent());
        assertEquals(Map.of("fixture", true), hit.meta());
    }

    @Test void changedProgramOrOptionsAndErrorsDoNotPopulateCache() {
        for (boolean async : List.of(false, true)) {
            for (String outcome : List.of("revision", "options", "error", "cancel")) {
                backend.getCache().clear();
                backend.setAsyncExecutionEnabled(async);
                tool.error = outcome.equals("error");
                tool.effect = () -> {
                    if (outcome.equals("revision")) revision.incrementAndGet();
                    if (outcome.equals("options")) tool.options += "changed";
                };
                tool.cancel = outcome.equals("cancel");
                if (async) runAsync(); else backend.callTool(tool.getName(), args);
                if (async || !outcome.equals("cancel")) assertEquals(0, backend.getCache().size(), outcome);
            }
        }
    }

    @Test void programEditsInvalidateEarlierSuccessfulResults() {
        backend.setAsyncExecutionEnabled(false);
        backend.callTool(tool.getName(), args);
        revision.incrementAndGet();
        backend.callTool(tool.getName(), args);
        assertEquals(2, tool.calls.get());
    }

    @Test void cacheKeysAreCanonicalAndDoNotUseLossyStringHashes() {
        McpCache cache = new McpCache();
        Map<String,Object> left = new LinkedHashMap<>();
        left.put("z", Map.of("b", 2, "a", 1)); left.put("a", 3);
        Map<String,Object> right = new LinkedHashMap<>();
        right.put("a", 3); right.put("z", Map.of("a", 1, "b", 2));
        assertEquals(cache.generateKey("q", left, "p"), cache.generateKey("q", right, "p"));
        assertEquals("Aa".hashCode(), "BB".hashCode());
        assertNotEquals(cache.generateKey("q", Map.of("value", "Aa"), "p"),
            cache.generateKey("q", Map.of("value", "BB"), "p"));
    }

    void runAsync() {
        Set<String> oldIds = new HashSet<>();
        backend.getTaskManager().listTasks(null).forEach(t -> oldIds.add(t.getTaskId()));
        backend.callTool(tool.getName(), args);
        McpTask task = backend.getTaskManager().listTasks(null).stream()
            .filter(t -> !oldIds.contains(t.getTaskId())).findFirst().orElseThrow();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!task.isTerminal() && System.nanoTime() < deadline) LockSupport.parkNanos(1_000_000);
        assertTrue(task.isTerminal());
    }

    static String text(McpSchema.CallToolResult r) { return ((McpSchema.TextContent) r.content().get(0)).text(); }
    static Program program(String name, AtomicLong revision) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[]{Program.class}, (p,m,a) -> switch(m.getName()) {
            case "getName" -> name;
            case "getDomainFile" -> null;
            case "getModificationNumber" -> revision.get();
            case "isClosed" -> false;
            case "addConsumer", "isUsedBy" -> true;
            case "release" -> null;
            case "equals" -> p == a[0];
            case "hashCode" -> System.identityHashCode(p);
            default -> throw new UnsupportedOperationException(m.getName());
        });
    }

    final class Backend extends GhidrAssistMCPBackend {
        Program active = target;
        @Override public Program getCurrentProgram() { return active; }
        @Override public List<Program> getAllOpenPrograms() { return List.of(target, windowA, windowB); }
    }
    static final class Query implements McpTool {
        final AtomicInteger calls = new AtomicInteger();
        volatile String options = "initial";
        boolean error, cancel;
        Runnable effect = () -> {};
        public String getName() { return "cache_query_fixture"; }
        public String getDescription() { return "Cache regression fixture"; }
        public McpSchema.JsonSchema getInputSchema() { return null; }
        public boolean isCacheable() { return true; }
        public boolean isLongRunning() { return true; }
        public String getCacheDiscriminator(Map<String,Object> a, Program p, GhidrAssistMCPBackend b) { return options; }
        public McpSchema.CallToolResult execute(Map<String,Object> a, Program p) {
            calls.incrementAndGet(); effect.run();
            return McpSchema.CallToolResult.builder().isError(error).addTextContent("query result")
                .structuredContent(Map.of("value", 42)).meta(Map.of("fixture", true)).build();
        }
        public McpSchema.CallToolResult execute(Map<String,Object> a, Program p, GhidrAssistMCPBackend b, McpTask t) {
            if (cancel) t.requestCancellation();
            return execute(a, p);
        }
    }
}
