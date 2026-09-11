package ghidrassistmcp.bsim;

import java.util.List;
import java.util.Map;
import ghidra.util.task.TaskMonitor;

/** Typed operation descriptor shared by the MCP adapter and persistent jobs. */
public record BsimOperation(String name, String description, Map<String, Object> properties,
        List<String> required, boolean readOnly, boolean destructive, boolean longRunning, Handler handler) {
    @FunctionalInterface public interface Handler {
        Map<String, Object> execute(BsimContext context, Map<String, Object> arguments,
            TaskMonitor monitor) throws Exception;
    }
    public static BsimOperation of(String name, String description, Map<String, Object> properties,
            List<String> required, boolean readOnly, boolean destructive, boolean longRunning, Handler handler) {
        return new BsimOperation(name, description, properties, required, readOnly, destructive, longRunning, handler);
    }
}
