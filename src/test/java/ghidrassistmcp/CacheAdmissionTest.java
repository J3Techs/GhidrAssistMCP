package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import ghidrassistmcp.cache.McpCache;
import io.modelcontextprotocol.spec.McpSchema;

class CacheAdmissionTest {
    @Test void oversizeResultsAreRejectedAndByteAccountingSurvivesReplacementAndInvalidation() {
        McpCache cache = new McpCache(3, 60_000, 2000, 1000);
        var small = result("small");
        cache.put("a", small, "", 0);
        cache.put("b", small, "", 0);
        long before = cache.getSerializedBytes();
        cache.put("a", small, "", 0);
        assertEquals(2, cache.size()); assertEquals(before, cache.getSerializedBytes());
        cache.put("oversize", result("x".repeat(2000)), "", 0);
        assertFalse(cache.containsKey("oversize")); assertEquals(1, cache.getRejectedCount());
        cache.invalidateProgram(""); assertEquals(0, cache.getSerializedBytes());
        cache.put("a", small, "", 0); cache.clear();
        assertEquals(0, cache.getSerializedBytes());
    }

    @Test void concurrentAdmissionHonorsEntryAndSerializedByteBudgets() throws Exception {
        McpCache cache = new McpCache(5, 60_000, 1400, 1000);
        try (var pool = Executors.newFixedThreadPool(8)) {
            var futures = new java.util.ArrayList<java.util.concurrent.Future<?>>();
            for (int i = 0; i < 100; i++) {
                final String key = "entry-" + i;
                futures.add(pool.submit(() -> cache.put(key, result("x".repeat(300)), "", 0)));
            }
            pool.shutdown(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
            for (var future : futures) future.get();
        }
        assertTrue(cache.size() > 0 && cache.size() <= 5);
        assertTrue(cache.getSerializedBytes() <= 1400);
    }

    @Test void invalidCapacitiesFailAndErrorResultsNeverEnterCache() {
        assertThrows(IllegalArgumentException.class, () -> new McpCache(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new McpCache(1, -1));
        McpCache cache = new McpCache();
        cache.put("bad", McpSchema.CallToolResult.builder().isError(true).addTextContent("failed").build(), "", 0);
        assertEquals(0, cache.size()); assertEquals(0, cache.getSerializedBytes());
    }

    private static McpSchema.CallToolResult result(String value) {
        return McpSchema.CallToolResult.builder().addTextContent(value).build();
    }
}
