package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class FunctionInventoryToolContractTest {
    @Test
    void exposesStructuredInventoryContractWithoutAProgram() {
        FunctionInventoryTool tool = new FunctionInventoryTool();
        assertTrue(tool.isCacheable());
        assertNotNull(tool.getInputSchema());
        assertTrue(tool.getDescription().contains("JSON"));
        assertTrue(tool.execute(Map.of(), null).isError());
    }
}
