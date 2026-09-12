package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import ghidrassistmcp.resources.RuntimeCapabilitiesResource;
import org.junit.jupiter.api.Test;

class DiagnosticPurityTest {
    @Test void injectedBackendDoesNotCreateOrReplaceGlobalGuiManager() throws Exception {
        var field = GhidrAssistMCPManager.class.getDeclaredField("instance");
        field.setAccessible(true);
        Object original = field.get(null);
        var backend = new GhidrAssistMCPBackend() {
            @Override public boolean isHeadlessSession() { return true; }
            @Override public ghidra.framework.model.Project getProject() { return null; }
        };
        try {
            field.set(null, null);
            assertFalse(new RuntimeCapabilitiesResource(() -> backend).snapshot().get("program_manager_available").equals(true));
            assertFalse(Boolean.TRUE.equals(backend.callTool("runtime_capabilities", null).isError()));
            assertNull(field.get(null));
            field.set(null, original);
            new RuntimeCapabilitiesResource(() -> backend).snapshot();
            assertSame(original, field.get(null));
        } finally { field.set(null, original); backend.getTaskManager().shutdown(); }
    }

    @Test void bindDefaultsRequireLoopbackAndExplicitRemoteOverride() throws Exception {
        assertTrue(java.net.InetAddress.getByName(GhidrAssistMCPServer.checkedBindHost("localhost", false)).isLoopbackAddress());
        assertEquals("127.0.0.1", GhidrAssistMCPServer.checkedBindHost("127.0.0.1", false));
        assertThrows(IllegalArgumentException.class, () -> GhidrAssistMCPServer.checkedBindHost("0.0.0.0", false));
        assertThrows(IllegalArgumentException.class, () -> GhidrAssistMCPServer.checkedBindHost("::", false));
        assertThrows(IllegalArgumentException.class, () -> GhidrAssistMCPServer.checkedBindHost(null, false));
        assertEquals("0.0.0.0", GhidrAssistMCPServer.checkedBindHost("0.0.0.0", true));
    }
}
