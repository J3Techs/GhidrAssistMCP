package ghidrassistmcp.scripts;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class HeadlessLauncherLifetimeTest {
    @Test void defaultAndExplicitWaitRetainTheCallerProject() {
        assertDoesNotThrow(() -> GAMCPStartServerScript.validateWaitMode(null));
        assertDoesNotThrow(() -> GAMCPStartServerScript.validateWaitMode(new String[] {"port=8080"}));
        assertDoesNotThrow(() -> GAMCPStartServerScript.validateWaitMode(new String[] {"wait=true"}));
    }
    @Test void falseAndMalformedWaitAreRejectedBeforeServerStartup() {
        for (String value : new String[] {"wait=false", "wait=", "wait=perhaps"})
            assertThrows(IllegalArgumentException.class, () -> GAMCPStartServerScript.validateWaitMode(new String[] {value}));
        assertThrows(IllegalArgumentException.class, () -> GAMCPStartServerScript.validateWaitMode(new String[] {"wait", "false"}));
    }

    @Test void launcherNormalizesAnalyzeHeadlessSplitAndEqualsForms() {
        GAMCPStartServerScript.ParsedArgs options = GAMCPStartServerScript.parseArguments(new String[] {
            "host", "127.0.0.1", "port", "18080", "wait", "true",
            "completion_file=C:\\Program Files\\GhidrAssist\\done=1",
            "tool_profile", "analysis profile", "unknown", "preserved"
        });
        assertEquals("127.0.0.1", options.host);
        assertEquals(18080, options.port);
        assertEquals("C:\\Program Files\\GhidrAssist\\done=1", options.completionFile);
        assertEquals("analysis profile", options.toolProfile);
    }

    @Test void missingKnownSplitValueFailsClearly() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
            () -> GAMCPStartServerScript.parseArguments(new String[] {"host", "port", "18080"}));
        assertTrue(error.getMessage().contains("host"));
    }
}
