package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Saves the program database, without closing it or checking it into a repository. */
public class SaveProgramTool implements McpTool {
    private final Supplier<Project> projects;
    public SaveProgramTool() { this(ProjectToolSupport::activeProject); }
    SaveProgramTool(Supplier<Project> projects) { this.projects = projects; }
    @Override public String getName() { return "save_program"; }
    @Override public String getDescription() {
        return "Save an open program without closing it. Uses program_name/current program or an exact project path. " +
            "Refuses active transactions, busy or read-only files; reports whether unsaved changes remain. " +
            "Does not check in, checkout, force unlock, or save FrontEnd session metadata.";
    }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isIdempotent() { return true; }
    @Override public boolean isLongRunning() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of("path", Map.of("type", "string",
            "description", "Optional exact Ghidra project file path; must already be open.")), List.of(), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return save(args, program, TaskMonitor.DUMMY);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        return save(args, program, new McpTaskMonitor(task, 0, 100, "Saving program"));
    }
    private McpSchema.CallToolResult save(Map<String, Object> args, Program program, TaskMonitor monitor) {
        Object consumer = new Object();
        DomainObject opened = null;
        try {
            DomainFile file;
            if (args.containsKey("path")) {
                Project project = projects.get();
                if (project == null) return ProjectToolSupport.error("No active Ghidra project");
                file = ProjectToolSupport.file(project.getProjectData().getRootFolder(),
                    ProjectToolSupport.required(args, "path"));
            } else {
                file = program == null || program.isClosed() ? null : program.getDomainFile();
            }
            if (file == null) return ProjectToolSupport.error("No target program file found");
            if (!file.isOpen()) return ProjectToolSupport.error("Program must already be open: " + file.getPathname());
            opened = file.getOpenedDomainObject(consumer);
            if (!(opened instanceof Program) || opened.isClosed()) return ProjectToolSupport.error("Target is not an open program");
            if (file.isBusy() || opened.getCurrentTransactionInfo() != null) {
                return ProjectToolSupport.error("Program has an active transaction or is busy; retry after it finishes");
            }
            boolean changed = opened.isChanged();
            if (!changed) return ProjectToolSupport.result(Map.of("path", file.getPathname(),
                "saved", false, "no_changes", true, "dirty_after", false));
            if (!file.canSave() || file.isReadOnly() || !opened.canSave() || !opened.isChangeable()) {
                return ProjectToolSupport.error("Program is not writable/saveable; checkout may be required");
            }
            monitor.checkCancelled();
            file.save(monitor);
            if (opened.isChanged()) return ProjectToolSupport.error("Save returned, but unsaved changes remain; program may have changed concurrently");
            return ProjectToolSupport.result(Map.of("path", file.getPathname(), "saved", true,
                "dirty_before", changed, "dirty_after", false, "open", file.isOpen()));
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (opened != null) opened.release(consumer);
        }
    }
}
