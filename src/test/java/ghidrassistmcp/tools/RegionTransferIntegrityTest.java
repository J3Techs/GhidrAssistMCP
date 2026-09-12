package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Contract checks for reviewed bulk region transfer plans. */
class RegionTransferIntegrityTest {
    @Test
    void regionTransferDeclaresReviewedPlanAndAtomicOutcomeFields() {
        var tool = new BulkRegionTransferTool();
        String input = tool.getInputSchema().toString();
        assertTrue(input.contains("preview_token"), input);
        assertTrue(input.contains("name_policy"), input);
        Map<String, Object> schema = tool.getOutputSchema();
        Map<?, ?> properties = (Map<?, ?>) schema.get("properties");
        assertTrue(properties.containsKey("preview_token"));
        assertTrue(properties.containsKey("labels_rolled_back"));
        assertTrue(properties.containsKey("functions_rolled_back"));
    }

    @Test
    void regionTransferRemainsExplicitlyMutatingAndArchitectureQualified() {
        var tool = new BulkRegionTransferTool();
        assertFalse(tool.isReadOnly());
        assertTrue(tool.isIdempotent());
        assertTrue(tool.getDescription().contains("atomic"));
    }
}
