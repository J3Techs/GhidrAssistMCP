package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AggregateQueryBudgetTest {
    @Test void oversizedUtf8AggregateReturnsCompleteSizeError() {
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("results", "😀".repeat(100_000));
        var result = BatchQuerySupport.boundedResult(payload);
        assertTrue(Boolean.TRUE.equals(result.isError()));
        assertTrue(((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text().contains("RESULT_TOO_LARGE"));
    }

    @Test void smallEscapedPayloadRemainsStructured() {
        var result = BatchQuerySupport.boundedResult(Map.of("results", java.util.List.of(Map.of("text", "quotes \" and \\ slash"))));
        assertFalse(Boolean.TRUE.equals(result.isError()));
        assertNotNull(result.structuredContent());
    }
}
