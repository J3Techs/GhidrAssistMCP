package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ProjectToolSupportTest {
    @Test void queuedMutationRequiresCapturedProjectIdentity() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> ProjectToolSupport.verifyProject(Map.of("__project_identity", ""), null));
        assertTrue(error.getMessage().contains("submission project"));
    }
}
