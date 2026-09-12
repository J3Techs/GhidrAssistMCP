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
}
