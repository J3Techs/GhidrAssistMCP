package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

class InlineReadCompletionTest {
    private static final class Tool implements McpTool {
        final AtomicInteger calls=new AtomicInteger(); final CountDownLatch entered=new CountDownLatch(1); final CountDownLatch release=new CountDownLatch(1); final boolean fail; final boolean readOnly;
        Tool(boolean fail){this(fail,true);} Tool(boolean fail, boolean readOnly){this.fail=fail;this.readOnly=readOnly;}
        public String getName(){return "inline_test";} public String getDescription(){return "test";}
        public McpSchema.JsonSchema getInputSchema(){return new McpSchema.JsonSchema("object",Map.of(),List.of(),null,null,null);}
        public McpSchema.CallToolResult execute(Map<String,Object>a,Program p){ calls.incrementAndGet(); entered.countDown(); try{release.await(2,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();} return McpSchema.CallToolResult.builder().isError(fail).addTextContent(fail?"failed":"done").build(); }
        public boolean isLongRunning(){return true;} public boolean isReadOnly(){return readOnly;}
    }
    private static String taskId(McpSchema.CallToolResult r){return (String)((Map<?,?>)r.structuredContent()).get("task_id");}

    @Test void queueRejectionReturnsRetryableErrorWithoutPublishingTask() throws Exception {
        var backend = new GhidrAssistMCPBackend();
        var started = new CountDownLatch(4);
        var release = new CountDownLatch(1);
        try {
            for (int i = 0; i < 4; i++) backend.getTaskManager().submitTask("hold", Map.of(), () -> {
                started.countDown();
                try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                return McpSchema.CallToolResult.builder().addTextContent("done").build();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            for (int i = 0; i < 64; i++) backend.getTaskManager().submitTask("queued", Map.of(), () ->
                McpSchema.CallToolResult.builder().addTextContent("done").build());
            var tool = new Tool(false);
            backend.registerTool(tool);
            var result = backend.callTool("inline_test", Map.of());
            assertTrue(result.isError());
            var body = (Map<?, ?>) result.structuredContent();
            assertEquals("SERVER_BUSY", body.get("error"));
            assertEquals(true, body.get("retryable"));
            assertFalse(body.containsKey("task_id"));
            assertEquals(68, backend.getTaskManager().listTasks(null).size());
            assertEquals(0, tool.calls.get());
        } finally { release.countDown(); backend.shutdownWorkers(); }
    }

    @Test void fastReadReturnsOriginalResultInline() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{Tool t=new Tool(false);b.registerTool(t); t.release.countDown(); var r=b.callTool("inline_test",Map.of()); assertFalse(r.isError()); assertTrue(((McpSchema.TextContent)r.content().get(0)).text().contains("done")); assertEquals(1,t.calls.get());}finally{b.shutdownWorkers();} }
    @Test void slowReadFallsBackToSameTaskWithoutDuplicateExecution() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{Tool t=new Tool(false);b.registerTool(t); var r=b.callTool("inline_test",Map.of()); String id=taskId(r); assertNotNull(id); assertEquals(1,t.calls.get()); t.release.countDown(); t.entered.await(1,TimeUnit.SECONDS); for(int i=0;i<100&&b.getTaskManager().getTask(id).isTerminal()==false;i++)Thread.sleep(5); assertEquals(1,t.calls.get()); assertTrue(b.getTaskManager().getTask(id).isTerminal());}finally{b.shutdownWorkers();} }
    @Test void zeroGracePreservesImmediateSubmission() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{b.setAsyncReadGraceMillis(0); Tool t=new Tool(false);b.registerTool(t); var r=b.callTool("inline_test",Map.of()); assertNotNull(taskId(r)); assertTrue(t.entered.await(1,TimeUnit.SECONDS)); assertEquals(1,t.calls.get()); t.release.countDown();}finally{b.shutdownWorkers();} }
    @Test void asyncReadErrorsAreReturnedAfterInlineWait() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{Tool t=new Tool(true);b.registerTool(t); t.release.countDown(); var r=b.callTool("inline_test",Map.of()); assertTrue(r.isError()); assertTrue(((McpSchema.TextContent)r.content().get(0)).text().contains("failed"));}finally{b.shutdownWorkers();} }
    @Test void mutationAsyncToolsRemainImmediate() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{Tool t=new Tool(false,false);b.registerTool(t); var r=b.callTool("inline_test",Map.of()); assertNotNull(taskId(r)); t.release.countDown();}finally{b.shutdownWorkers();} }
    @Test void interruptedGraceReturnsExistingTaskAndPreservesInterrupt() throws Exception { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{Tool t=new Tool(false);b.registerTool(t); var result=new java.util.concurrent.atomic.AtomicReference<McpSchema.CallToolResult>(); var interrupted=new java.util.concurrent.atomic.AtomicBoolean(); Thread caller=new Thread(()->{result.set(b.callTool("inline_test",Map.of())); interrupted.set(Thread.currentThread().isInterrupted());}); caller.start(); assertTrue(t.entered.await(1,TimeUnit.SECONDS)); caller.interrupt(); caller.join(1500); assertNotNull(result.get()); assertNotNull(taskId(result.get())); assertTrue(interrupted.get()); t.release.countDown();}finally{b.shutdownWorkers();} }
    @Test void graceSetterRejectsOutOfRange() { GhidrAssistMCPBackend b=new GhidrAssistMCPBackend(); try{assertThrows(IllegalArgumentException.class,()->b.setAsyncReadGraceMillis(-1));assertThrows(IllegalArgumentException.class,()->b.setAsyncReadGraceMillis(1001));}finally{b.shutdownWorkers();} }
}
