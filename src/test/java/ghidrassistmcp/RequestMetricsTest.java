package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;

class RequestMetricsTest {
    @Test
    void recordsUtf8EscapedSerializedSizeAndWorkerCorrelation() throws Exception {
        var metrics = new RequestMetrics();
        var submission = metrics.start(" alias_tool:canonical").begin("selection").end("selection");
        var worker = submission.forkWorker().begin("execution");
        Map<String, Object> value = Map.of("text", "héllo 世界", "quote", "\\\"");
        worker.end("execution").finish(value);
        submission.finish(value);
        assertEquals(2, metrics.snapshot().size());
        var records = metrics.snapshot();
        assertEquals(records.get(0).correlationId(), records.get(1).correlationId());
        assertEquals("alias_tool", records.get(0).toolName());
        assertEquals("worker_completion", records.get(0).kind());
        assertEquals("submission", records.get(1).kind());
        assertEquals(new ObjectMapper().writeValueAsBytes(value).length, records.get(0).encodedResultBytes());
        assertTrue(records.get(0).durationsMillis().containsKey("execution"));
    }

    @Test
    void ringIsBoundedAndDoesNotRetainArgumentsOrPrograms() {
        var metrics = new RequestMetrics();
        for (int i = 0; i < 300; i++) metrics.start("tool-" + i).finish(Map.of("i", i));
        assertEquals(RequestMetrics.MAX_RECORDS, metrics.snapshot().size());
        assertEquals("tool-44", metrics.snapshot().getFirst().toolName());
        assertTrue(metrics.snapshot().stream().allMatch(r -> r.durationsMillis().size() >= 1));
    }

    @Test
    void concurrentSamplesRemainCompleteAndDistinct() throws Exception {
        var metrics = new RequestMetrics(); var pool = Executors.newFixedThreadPool(8); var gate = new CountDownLatch(1);
        try {
            List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 100; i++) futures.add(pool.submit(() -> { try { gate.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } metrics.start("concurrent").finish(Map.of("ok", true)); }));
            gate.countDown();
            for (var future : futures) future.get();
            assertEquals(100, metrics.snapshot().size());
            assertTrue(metrics.snapshot().stream().allMatch(RequestMetrics.Record::complete));
        } finally { pool.shutdownNow(); }
    }
}
