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
    }
}
