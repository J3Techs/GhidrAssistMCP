package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class McpRequestContextTest {
    @Test void scopesAreRestoredAndNeverInheritedByBackgroundWorkers() throws Exception {
        List<Double> seen = new ArrayList<>();
        try (var worker = Executors.newSingleThreadExecutor()) {
            McpRequestContext.callWithProgress((p, t, m) -> seen.add(p), () -> {
                assertTrue(McpRequestContext.hasProgressReporter());
                try { assertFalse(worker.submit(McpRequestContext::hasProgressReporter).get()); }
                catch (Exception e) { throw new RuntimeException(e); }
                McpRequestContext.reportProgress(0, 1.0, "started");
                McpRequestContext.callWithProgress(null, () -> {
                    assertFalse(McpRequestContext.hasProgressReporter());
                    McpRequestContext.reportProgress(1, 1.0, "not subscribed");
                    return null;
                });
                McpRequestContext.reportProgress(1, 1.0, "complete");
                return null;
            });
        }
        assertEquals(List.of(0.0, 1.0), seen);
        assertFalse(McpRequestContext.hasProgressReporter());
        assertThrows(IllegalStateException.class, () -> McpRequestContext.callWithProgress((p, t, m) -> {}, () -> {
            throw new IllegalStateException("tool failed");
        }));
        assertFalse(McpRequestContext.hasProgressReporter());
    }

    @Test void rejectsNonIncreasingValuesAndTransportFailureDoesNotFailOperation() {
        List<Double> seen = new ArrayList<>();
        McpRequestContext.callWithProgress((p, t, m) -> seen.add(p), () -> {
            for (double value : new double[] {0, 0, -1, Double.NaN, 2, 1, 3})
                McpRequestContext.reportProgress(value, null, "progress");
            return null;
        });
        assertEquals(List.of(0.0, 2.0, 3.0), seen);
        assertEquals("result", McpRequestContext.callWithProgress((p, t, m) -> { throw new IllegalStateException("closed"); }, () -> {
            McpRequestContext.reportProgress(0, null, "started");
            assertFalse(McpRequestContext.hasProgressReporter());
            return "result";
        }));
        assertFalse(McpRequestContext.hasProgressReporter());
    }
}
