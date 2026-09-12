package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class OperatingGuideTest {
    @Test void initializationUsesPackagedBoundedGuide() throws Exception {
        try (var in = OperatingGuide.class.getResourceAsStream(OperatingGuide.RESOURCE)) {
            assertNotNull(in, "The extension must package its operating guide");
            byte[] bytes = in.readAllBytes();
            assertTrue(bytes.length <= 8192, "Connect-time guidance has an 8 KiB budget");
            assertEquals(new String(bytes, StandardCharsets.UTF_8).strip(), OperatingGuide.text());
        }
    }
}
