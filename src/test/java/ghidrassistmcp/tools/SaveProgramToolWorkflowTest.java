package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.util.ArrayList;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SaveProgramToolWorkflowTest {
    @Test void batchSaveRejectsUnboundedSelection() {
        var paths = new ArrayList<String>();
        for (int i = 0; i < 101; i++) paths.add("/program-" + i);
        var result = new SaveProgramTool().execute(Map.of("paths", paths), null);
        assertTrue(Boolean.TRUE.equals(result.isError()));
        assertTrue(result.content().toString().contains("1 to 100"));
    }
}
