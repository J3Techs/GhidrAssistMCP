package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

class MatcherBoundsTest {
    @Test void searchPatternRejectsOversizedNormalizedInputBeforeAllocation() throws Exception {
        Method parser = SearchBytesTool.class.getDeclaredMethod("parsePattern", String.class);
        parser.setAccessible(true);
        String oversized = "aa".repeat(InstructionMaskBuilder.MAX_PATTERN_BYTES + 1);
        InvocationTargetException error = assertThrows(InvocationTargetException.class, () -> parser.invoke(null, oversized));
        assertTrue(error.getCause().getMessage().contains("pattern"));
    }
}
