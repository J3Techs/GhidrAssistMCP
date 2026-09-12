package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;

/** Auditable snapshot of the real registry; does not open a project or execute tools. */
class ToolCatalogInventoryTest {
    @Test
    void everyRegisteredToolHasAnObjectSchemaAndUniqueName() throws Exception {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            var tools = backend.getAllTools().stream().sorted(Comparator.comparing(McpSchema.Tool::name)).toList();
            Set<String> names = new HashSet<>();
            for (var tool : tools) {
                assertTrue(names.add(tool.name()), tool.name());
                assertEquals("object", tool.inputSchema().get("type"), tool.name());
                assertNotNull(tool.description(), tool.name());
                assertFalse(tool.description().isBlank(), tool.name());
                assertNotNull(tool.annotations(), tool.name());
            }
            Path output = Path.of("build", "reports", "tool-catalog.json");
            Files.createDirectories(output.getParent());
            var disabled = tools.stream().map(McpSchema.Tool::name).filter(name -> !backend.isToolEnabled(name)).toList();
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(), Map.of(
                "registered_count", tools.size(), "enabled_count", tools.size() - disabled.size(),
                "disabled_by_default", disabled, "tools", tools));
        } finally { backend.getTaskManager().shutdown(); }
    }
}
