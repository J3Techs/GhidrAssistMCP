package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Contract tests for the post-commit verification envelope. */
class PostMutationCodeTest {
    @Test
    void invalidBoundsAreRejectedBeforeMutation() {
        assertNotNull(PostMutationCode.validateOptions(Map.of("max_chars", 0)));
        assertNotNull(PostMutationCode.validateOptions(Map.of("verification_timeout_seconds", 301)));
        assertNotNull(PostMutationCode.validateOptions(Map.of("return_code", "yes")));
    }

    @Test
    void missingVerifierReportsCommittedButUnavailable() {
        var result = PostMutationCode.result(null, null, "int f(void)", null, Map.of());
        assertFalse(result.isError());
        @SuppressWarnings("unchecked") var body = (Map<String, Object>) result.structuredContent();
        assertEquals("committed", body.get("mutation_status"));
        assertEquals("unavailable", body.get("verification_status"));
        assertEquals("int f(void)", body.get("stored_prototype"));
        assertFalse(body.containsKey("code"));
    }
}
