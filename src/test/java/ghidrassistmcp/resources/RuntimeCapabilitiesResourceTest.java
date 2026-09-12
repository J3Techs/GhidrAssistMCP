package ghidrassistmcp.resources;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RuntimeCapabilitiesResourceTest {
    @Test void noProjectReportIsStructuredAndDoesNotProbeRemotes() throws Exception {
        var resource = new RuntimeCapabilitiesResource(() -> null);
        assertTrue(resource.canHandle("ghidra://runtime/capabilities"));
        assertFalse(resource.canHandle("ghidra://runtime/other"));
        Map<?, ?> report = new ObjectMapper().readValue(resource.readContent(null, Map.of()), Map.class);
        assertEquals(false, report.get("program_manager_available"));
        assertTrue(((java.util.List<?>) report.get("unavailable_reasons")).toString().contains("not probed"));
        assertNotNull(report.get("tasks"));
    }

    @Test void headlessFlagIsExposedWithoutAProject() throws Exception {
        var resource = new RuntimeCapabilitiesResource(() -> null);
        Map<?, ?> report = new ObjectMapper().readValue(resource.readContent(null, Map.of()), Map.class);
        assertEquals(Boolean.valueOf(java.awt.GraphicsEnvironment.isHeadless()), report.get("headless"));
        assertNotNull(report.get("build_info"));
    }

    @Test void toolAndResourceExposeTheSameCapabilitiesWithoutAdvertisingUnsupportedTasks() throws Exception {
        var backend = new ghidrassistmcp.GhidrAssistMCPBackend();
        try {
            var result = new ghidrassistmcp.tools.RuntimeCapabilitiesTool().execute(Map.of(), null, backend);
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            var validator = io.modelcontextprotocol.json.McpJsonDefaults.getSchemaValidator();
            var schema = new ghidrassistmcp.tools.RuntimeCapabilitiesTool().getOutputSchema();
            assertTrue(validator.validate(schema, body).valid());
            var malformed = new java.util.LinkedHashMap<Object, Object>(body);
            malformed.put("protocol", Map.of("sdk_version", "2.0.1"));
            assertFalse(validator.validate(schema, malformed).valid());
            Map<?, ?> resource = new ObjectMapper().readValue(new RuntimeCapabilitiesResource(() -> backend).readContent(null, Map.of()), Map.class);
            assertEquals(resource.get("registered_tools"), body.get("registered_tools"));
            assertEquals(backend.getAllTools().size(), body.get("registered_tools"));
            assertEquals("2025-11-25", ((Map<?, ?>) body.get("protocol")).get("latest_supported_revision"));
            assertEquals(false, ((Map<?, ?>) body.get("protocol")).get("tasks_extension"));
            assertNotNull(backend.getAvailableTools().stream().filter(t -> t.name().equals("runtime_capabilities")).findFirst().orElseThrow().outputSchema());
        } finally { backend.getTaskManager().shutdown(); }
    }
}
