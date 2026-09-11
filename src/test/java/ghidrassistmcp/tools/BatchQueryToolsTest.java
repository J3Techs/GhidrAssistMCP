package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Focused bounded-query tests that do not open Ghidra or execute scripts. */
class BatchQueryToolsTest {
    @Test void decodesExplicitEndianAndSignedValues() {
        assertEquals(0x01020304L, BatchQuerySupport.decodeInteger("04030201", "little", "u32"));
        assertEquals(0x01020304L, BatchQuerySupport.decodeInteger("01020304", "big", "u32"));
        assertEquals(-2L, BatchQuerySupport.decodeInteger("feff", "little", "i16"));
        assertEquals(-2L, BatchQuerySupport.decodeInteger("fffe", "big", "i16"));
        assertEquals("18446744073709551615", BatchQuerySupport.decodeInteger("ffffffffffffffff", "big", "u64"));
        assertEquals("18446744073709551615", BatchQuerySupport.decodeInteger("ffffffffffffffff", "little", "u64"));
    }

    @Test void capsRejectOverflowAndLargeRequests() {
        assertEquals(BatchQuerySupport.MAX_BYTES, BatchQuerySupport.checkedTotal(0, BatchQuerySupport.MAX_BYTES));
        assertThrows(IllegalArgumentException.class, () -> BatchQuerySupport.checkedTotal(BatchQuerySupport.MAX_BYTES, 1));
        assertThrows(IllegalArgumentException.class, () -> BatchQuerySupport.checkedTotal(Integer.MAX_VALUE, Integer.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> BatchQuerySupport.list(List.of("a", "b"), "addresses", 1));
    }

    @Test void symbolModesAreCaseInsensitiveAndGlobBounded() {
        assertTrue(BatchQuerySupport.matches("SrvX_IpoMapS16S16", "ipomap", "contains"));
        assertTrue(BatchQuerySupport.matches("FUN_8010", "fun_8010", "exact"));
        assertTrue(BatchQuerySupport.matches("FUN_8010", "FUN_*", "glob"));
        assertFalse(BatchQuerySupport.matches("FUN_8010", "DATA_*", "glob"));
    }

    @Test void allToolsDeclareBatchInputsAndRemainReadOnlyWithoutProgram() {
        List<ghidrassistmcp.McpTool> tools = List.of(new QueryAddressContextBatchTool(), new SearchSymbolsBatchTool(),
            new ReadMemoryBatchTool(), new ReadMemoryTableTool(), new XrefsBatchTool());
        for (ghidrassistmcp.McpTool tool : tools) {
            assertNotNull(tool.getName());
            assertNotNull(tool.getInputSchema());
            assertEquals("No program currently loaded", ((io.modelcontextprotocol.spec.McpSchema.TextContent)
                tool.execute(Map.of(), null).content().get(0)).text());
        }
    }
}
