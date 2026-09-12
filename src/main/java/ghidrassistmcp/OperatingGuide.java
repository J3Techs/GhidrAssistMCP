package ghidrassistmcp;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Single packaged source for concise client-neutral initialization guidance. */
public final class OperatingGuide {
    public static final String RESOURCE = "/ghidrassistmcp/operating-guide.md";
    private static final String FALLBACK = "Start with runtime_capabilities and list_binaries; use exact program_id selectors. "
        + "Page results. Follow generic task IDs with wait_task and get_task_status; BSim jobs use separate controls. "
        + "A timeout or cancellation request does not prove execution stopped. Inspect outcomes and save_program results.";
    private static final String TEXT = load();
    private OperatingGuide() {}
    public static String text() { return TEXT; }
    private static String load() {
        try (InputStream in = OperatingGuide.class.getResourceAsStream(RESOURCE)) {
            if (in == null) return FALLBACK;
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8).strip();
            return text.isEmpty() ? FALLBACK : text;
        } catch (Exception error) { return FALLBACK; }
    }
}
