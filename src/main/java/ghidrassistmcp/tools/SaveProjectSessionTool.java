package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/** Saves FrontEnd project/session metadata separately from Program databases. */
public class SaveProjectSessionTool implements McpTool {
    @Override public String getName() { return "save_project_session"; }
    @Override public String getDescription() {
        return "Request a save of Ghidra FrontEnd project/session metadata. This is separate from save_program; " +
            "the native Project API does not expose a durable verification signal, so the result is explicitly unverified.";
    }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isIdempotent() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(), List.of(), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String,Object> args, Program program) {
        Project project = ProjectToolSupport.activeProject();
        if (project == null) return ProjectToolSupport.error("No active Ghidra project");
        try {
            ProjectToolSupport.verifyProject(args, project);
            if (SwingUtilities.isEventDispatchThread()) project.save();
            else SwingUtilities.invokeAndWait(project::save);
            return ProjectToolSupport.result(Map.of("metadata_save_requested", true,
                "verified", false, "warning", "Ghidra Project.save() has no durable verification result; Program databases require save_program."));
        } catch (Exception e) { return ProjectToolSupport.error("Project metadata save failed: " + e.getMessage()); }
    }
    @Override public McpSchema.CallToolResult execute(Map<String,Object> args, Program program, GhidrAssistMCPBackend backend) {
        if (backend != null && backend.isHeadlessSession()) return ProjectToolSupport.error("FrontEnd metadata save requires the GUI; save_program persists headless program databases");
        return execute(args, program);
    }
}
